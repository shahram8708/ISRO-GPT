from __future__ import annotations
from flask import current_app

import os
import uuid
from typing import List, Optional
from mistune import markdown
from xhtml2pdf import pisa
from io import BytesIO
from datetime import datetime
from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    flash,
    request,
    jsonify,
    send_file,
    abort,
    session,
)
from flask_login import (
    current_user,
    login_user,
    logout_user,
    login_required,
    AnonymousUserMixin,
)
from flask_wtf.csrf import generate_csrf
from werkzeug.utils import secure_filename
from sqlalchemy.orm import joinedload
from flask_mail import Mail
import flask_mail
import pdfplumber
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import random
from flask import session, jsonify
from config import Config
from extensions import db, login_manager, csrf, migrate
from forms import RegistrationForm, LoginForm, ContactForm
from models import User, Chat, Message, ChatParticipant, ShareLink
from google import genai

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in Config.ALLOWED_EXTENSIONS


def create_app(config_class=Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_class)

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    migrate.init_app(app, db)
    mail = Mail(app) 

    login_manager.login_view = "login"
    login_manager.login_message_category = "info"

    if app.config.get("GOOGLE_API_KEY"):
        try:
            genai.configure(api_key=app.config["GOOGLE_API_KEY"])
        except Exception as exc:
            app.logger.error("Failed to configure AI Model: %s", exc)

    def generate_ai_response(chat_id: int, prompt: str, attachments: Optional[List[dict]] = None) -> str:
        history = (
            Message.query
            .filter(Message.chat_id == chat_id)
            .order_by(Message.id.desc())
            .limit(5)
            .all()[::-1]
        )
                
        client = genai.Client(api_key=current_app.config["GOOGLE_API_KEY"])

        try:
            google_search_tool = genai.types.Tool(google_search=genai.types.GoogleSearch())
            config = genai.types.GenerateContentConfig(tools=[google_search_tool])
        except Exception:
            config = None 

        chat = client.chats.create(model="gemini-2.5-flash-lite", config=config)

        for msg in history:
            if msg.content and msg.role == "user":
                chat.send_message(msg.content)

        uploaded_parts = []
        if attachments:
            for a in attachments:
                try:
                    gfile = client.files.upload(
                        file=os.path.abspath(a["abs_path"]),
                        config={"mime_type": a["mime_type"]} if a.get("mime_type") else None,
                    )
                    part = genai.types.Part.from_uri(
                        file_uri=gfile.uri,
                        mime_type=gfile.mime_type or a.get("mime_type") or "application/octet-stream",
                    )
                    uploaded_parts.append(part)
                except Exception as e:
                    current_app.logger.error("GenAI upload failed for %s: %s", a.get("abs_path"), e)

        for p in uploaded_parts:
            try:
                chat.send_message(p)
            except Exception as e:
                current_app.logger.error("Sending file part failed: %s", e)

        try:
            response = chat.send_message(prompt or " ")
        except Exception:
            response = chat.send_message(genai.types.Part.from_text(text=prompt or " "))

        return (getattr(response, "text", None) or "").strip() or "No response."

    @app.context_processor
    def inject_globals():
        return {
            "csrf_token": generate_csrf,
        }

    @app.errorhandler(404)
    @app.errorhandler(403)
    @app.errorhandler(500)
    @app.errorhandler(Exception) 
    def handle_error(error):
        code = getattr(error, 'code', 500)
        message = getattr(error, 'description', str(error))
        return render_template("error.html", code=code, message=message), code

    @app.route("/")
    def index():
        return redirect(url_for("dashboard"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        form = RegistrationForm()
        if form.validate_on_submit():
            if not session.get('otp_verified'):
                flash("Please verify your email OTP before registering.", "danger")
                return render_template("register.html", form=form)

            try:
                user = User(username=form.username.data, email=form.email.data)
                user.set_password(form.password.data)
                db.session.add(user)
                db.session.commit()
                session.pop('otp_verified', None)
                session.pop('registration_otp', None)
                session.pop('registration_email', None)
                flash("Account created! You can now log in.", "success")
                return redirect(url_for("login"))
            except Exception as e:
                db.session.rollback()
                current_app.logger.error("Registration error: %s", e)
                flash("An error occurred during registration. Please try again.", "danger")
        return render_template("register.html", form=form)

    @app.route("/send_otp", methods=["POST"])
    def send_otp():
        data = request.get_json(force=True) or {}
        email = (data.get("email") or "").strip()
        if not email:
            return jsonify(success=False, message="Email is required"), 400

        otp = str(random.randint(100000, 999999))
        session['registration_otp'] = otp
        session['registration_email'] = email

        try:
            msg = flask_mail.Message(
                subject="Your ISRO-GPT OTP",
                recipients=[email],
                body=f"Your OTP for registration is: {otp}. It expires in 10 minutes."
            )
            mail.send(msg)
            return jsonify(success=True)
        except Exception as e:
            current_app.logger.error("Failed to send OTP: %s", e)
            return jsonify(success=False, message="Failed to send OTP"), 500

    @app.route("/verify_otp", methods=["POST"])
    def verify_otp():
        data = request.get_json() or {}
        email = data.get("email")
        otp = data.get("otp")

        if not email or not otp:
            return jsonify(success=False, message="Email and OTP are required")

        if session.get("registration_otp") == otp and session.get("registration_email") == email:
            session['otp_verified'] = True
            return jsonify(success=True)
        else:
            return jsonify(success=False, message="Invalid OTP")
        
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        form = LoginForm()
        if form.validate_on_submit():
            identifier = form.email.data
            user = User.query.filter(
                (User.email == identifier) | (User.username == identifier)
            ).first()
            if user and user.check_password(form.password.data):
                login_user(user, remember=True)
                return redirect(request.args.get("next") or url_for("dashboard"))
            else:
                flash("Invalid credentials. Please check your details.", "danger")
        return render_template("login.html", form=form)

    @app.before_request
    def make_session_permanent():
        if current_user.is_authenticated:
            session.permanent = True

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        flash("You have been logged out.", "info")
        return redirect(url_for("login"))

    @app.route("/dashboard")
    def dashboard():
        if isinstance(current_user, AnonymousUserMixin):
            chats = []
        else:
            chats = (
                Chat.query.join(ChatParticipant)
                .filter(ChatParticipant.user_id == current_user.id)
                .options(joinedload(Chat.messages))
                .order_by(Chat.created_at.desc())
                .all()
            )
        return render_template("dashboard.html", chats=chats)

    @app.route("/chat/new")
    @login_required
    def new_chat():
        empty_chat = (
            db.session.query(Chat)
            .join(ChatParticipant, ChatParticipant.chat_id == Chat.id)
            .outerjoin(Message, Message.chat_id == Chat.id)
            .filter(ChatParticipant.user_id == current_user.id)
            .group_by(Chat.id)
            .having(db.func.count(Message.id) == 0)
            .first()
        )

        if empty_chat:
            return redirect(url_for("chat_view", chat_id=empty_chat.id))

        chat = Chat(name="New Chat", owner=current_user)
        db.session.add(chat)
        db.session.flush()  
        
        participant = ChatParticipant(chat_id=chat.id, user_id=current_user.id, role="owner")
        db.session.add(participant)
        db.session.commit()

        return redirect(url_for("chat_view", chat_id=chat.id))

    @app.route("/chat/<int:chat_id>")
    @login_required
    def chat_view(chat_id: int):
        chat = Chat.query.options(joinedload(Chat.messages)).get_or_404(chat_id)
        participant = ChatParticipant.query.filter_by(chat_id=chat_id, user_id=current_user.id).first()
        if not participant:
            abort(403)
        messages = Message.query.filter_by(chat_id=chat_id).order_by(Message.id.asc()).all()
        chats = (
            Chat.query.join(ChatParticipant)
            .filter(ChatParticipant.user_id == current_user.id)
            .order_by(Chat.created_at.desc())
            .all()
        )
        return render_template(
            "chat.html",
            chat=chat,
            messages=messages,
            participant=participant,
            chats=chats,
        )

    @app.route("/chat/send/<int:chat_id>", methods=["POST"])
    @login_required
    def send_message(chat_id: int):
        chat = Chat.query.get_or_404(chat_id)
        participant = ChatParticipant.query.filter_by(chat_id=chat_id, user_id=current_user.id).first()
        if not participant or participant.role not in {"owner", "editor"}:
            return jsonify({"error": "You do not have permission to send messages."}), 403
        message_text = request.form.get("message", "").strip()
        files = request.files.getlist("files") if "files" in request.files else []
        file_paths: List[str] = []
        attachments: List[dict] = []
        extracted_text = ""

        for file in files:
            if file.filename == "":
                continue
            if not allowed_file(file.filename):
                return jsonify({"error": f"Unsupported file type: {file.filename}"}), 400

            filename = secure_filename(file.filename)
            unique_name = f"{uuid.uuid4().hex}_{filename}"
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], unique_name)
            file.save(file_path)
            file_paths.append(file_path)
            db_file_url = f"/static/uploads/{unique_name}"
            ext = filename.rsplit(".", 1)[1].lower()
            mime = file.mimetype or {
                "png":"image/png", "jpg":"image/jpeg","jpeg":"image/jpeg",
                "gif":"image/gif","webp":"image/webp","bmp":"image/bmp",
                "svg":"image/svg+xml","pdf":"application/pdf"
            }.get(ext, "application/octet-stream")

            attachments.append({
                "abs_path": os.path.abspath(file_path),
                "mime_type": mime,
                "name": unique_name,
                "ext": ext,
            })

            if ext == "pdf":
                try:
                    with pdfplumber.open(file_path) as pdf:
                        for page_num, page in enumerate(pdf.pages, start=1):
                            txt = page.extract_text() or ""
                            if txt:
                                extracted_text += f"\n\n--- Page {page_num} ---\n" + txt
                except Exception as e:
                    app.logger.error("PDF extraction error: %s", e)

        full_message = message_text
        if extracted_text:
            full_message = (message_text + "\n\n" + extracted_text).strip()
        user_msg = Message(
            chat_id=chat_id,
            user_id=current_user.id,
            role="user",
            content=message_text if message_text else None,
            file_path=",".join([f"{os.path.basename(p)}" for p in file_paths]) if file_paths else None,
        )
        db.session.add(user_msg)
        db.session.flush()
        ai_response = generate_ai_response(chat_id, full_message, attachments=attachments)
        ai_msg = Message(
            chat_id=chat_id,
            role="ai",
            content=ai_response,
        )
        db.session.add(ai_msg)
        db.session.commit()
        return jsonify({
            "messages": [user_msg.to_dict(), ai_msg.to_dict()],
        })

    @app.route("/chat/rename/<int:chat_id>", methods=["POST"])
    @login_required
    def rename_chat(chat_id: int):
        new_name = request.form.get("name", "").strip()
        if not new_name:
            return jsonify({"error": "Name cannot be empty"}), 400
        chat = Chat.query.get_or_404(chat_id)
        participant = ChatParticipant.query.filter_by(chat_id=chat_id, user_id=current_user.id).first()
        if not participant or participant.role != "owner":
            return jsonify({"error": "Only the chat owner can rename this chat."}), 403
        chat.name = new_name
        db.session.commit()
        return jsonify({"success": True, "name": new_name})

    @app.route("/chat/delete/<int:chat_id>", methods=["POST"])
    @login_required
    def delete_chat(chat_id: int):
        chat = Chat.query.get_or_404(chat_id)
        participant = ChatParticipant.query.filter_by(chat_id=chat_id, user_id=current_user.id).first()
        if not participant or participant.role != "owner":
            return jsonify({"error": "Only the chat owner can delete this chat."}), 403
        db.session.delete(chat)
        db.session.commit()
        return jsonify({"success": True})

    @app.route("/chat/search")
    @login_required
    def search_chats():
        query = request.args.get("q", "").strip()
        results = []
        if query:
            chat_results = (
                Chat.query.join(ChatParticipant)
                .filter(ChatParticipant.user_id == current_user.id)
                .filter(Chat.name.ilike(f"%{query}%"))
                .all()
            )
            message_results = (
                Message.query.join(Chat)
                .join(ChatParticipant)
                .filter(ChatParticipant.user_id == current_user.id)
                .filter(Message.content.ilike(f"%{query}%"))
                .all()
            )
            results = {
                "chats": [
                    {"id": c.id, "name": c.name, "preview": (c.messages[-1].content if c.messages else "")}
                    for c in chat_results
                ],
                "messages": [m.to_dict() for m in message_results],
            }
        return jsonify(results)

    @app.route("/chat/export/<int:chat_id>")
    @login_required
    def export_chat(chat_id: int):
        chat = Chat.query.get_or_404(chat_id)
        participant = ChatParticipant.query.filter_by(chat_id=chat_id, user_id=current_user.id).first()
        if not participant:
            abort(403)

        messages = Message.query.filter_by(chat_id=chat_id).order_by(Message.id.asc()).all()

        html_content = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Helvetica, Arial, sans-serif; margin: 40px; }}
                h1 {{ text-align: center; color: #2c3e50; }}
                .chat-header {{ font-size: 18px; margin-bottom: 20px; color: #34495e; }}
                .message {{ margin-bottom: 15px; padding: 10px; border-radius: 8px; }}
                .user {{ background-color: #ecf0f1; }}
                .ai {{ background-color: #d6eaf8; }}
                .timestamp {{ font-size: 10px; color: #7f8c8d; }}
                .attachment {{ font-size: 11px; color: #2980b9; margin-top: 5px; }}
            </style>
        </head>
        <body>
            <h1>Chat Export</h1>
            <div class="chat-header">Chat: {chat.name} (ID {chat.id})</div>
        """

        for msg in messages:
            timestamp = msg.created_at.strftime("%Y-%m-%d %H:%M")
            role_class = "user" if msg.role == "user" else "ai"
            prefix = "User" if msg.role == "user" else "AI"
            content_html = markdown(msg.content or "")

            html_content += f"""
            <div class="message {role_class}">
                <div class="timestamp">[{timestamp}] {prefix}</div>
                <div class="content">{content_html}</div>
            """
            if msg.file_path:
                html_content += f"<div class='attachment'>📎 Attachment: {msg.file_path}</div>"
            html_content += "</div>"

        html_content += "</body></html>"

        pdf_bytes = BytesIO()
        pisa_status = pisa.CreatePDF(html_content, dest=pdf_bytes)

        if pisa_status.err:
            abort(500, description="Error generating PDF")

        pdf_bytes.seek(0)
        export_name = f"chat_{chat_id}.pdf"
        return send_file(pdf_bytes, as_attachment=True, download_name=export_name, mimetype="application/pdf")

    @app.route("/forgot", methods=["GET"])
    def forgot():
        return render_template("forgot.html")

    @app.route("/send_otp", methods=["POST"])
    def send_forgot_otp():
        data = request.get_json(force=True) or {}
        email = (data.get("email") or "").strip().lower()
        if not email:
            return jsonify(success=False, message="Email is required"), 400

        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify(success=False, message="No account with that email was found."), 404

        otp = str(random.randint(100000, 999999))
        session['forgot_otp'] = otp
        session['forgot_email'] = email
        session['forgot_otp_sent_at'] = int(datetime.utcnow().timestamp())

        try:
            msg = flask_mail.Message(
                subject="ISRO-GPT Password Reset OTP",
                recipients=[email],
                body=f"Your password reset OTP is: {otp}\nIt is valid for 10 minutes."
            )
            mail.send(msg)
            return jsonify(success=True)
        except Exception as e:
            app.logger.error("Failed to send forgot OTP: %s", e)
            return jsonify(success=False, message="Failed to send OTP"), 500

    @app.route("/verify_otp", methods=["POST"])
    def verify_forgot_otp():
        data = request.get_json(force=True) or {}
        email = (data.get("email") or "").strip().lower()
        otp = (data.get("otp") or "").strip()

        if not email or not otp:
            return jsonify(success=False, message="Email and OTP are required"), 400

        sent_ts = session.get('forgot_otp_sent_at')
        if sent_ts and (int(datetime.utcnow().timestamp()) - sent_ts) > 600:
            return jsonify(success=False, message="OTP expired. Please request a new one."), 400

        if session.get("forgot_otp") == otp and session.get("forgot_email") == email:
            session['forgot_otp_verified'] = True
            session['forgot_email'] = email
            return jsonify(success=True)
        else:
            return jsonify(success=False, message="Invalid OTP"), 400

    @app.route("/reset_password", methods=["POST"])
    def reset_password():
        data = request.get_json(force=True) or {}
        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""
        confirm = data.get("confirm") or ""

        if not email or not password or not confirm:
            return jsonify(success=False, message="All fields are required"), 400
        if password != confirm:
            return jsonify(success=False, message="Passwords do not match"), 400

        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify(success=False, message="User not found"), 404

        try:
            user.set_password(password) 
            db.session.commit()

            for k in ('forgot_otp', 'forgot_email', 'forgot_otp_sent_at', 'forgot_otp_verified'):
                session.pop(k, None)

            return jsonify(success=True, message="Password reset successful. You can now log in.")
        except Exception as e:
            db.session.rollback()
            app.logger.error("Password reset error: %s", e)
            return jsonify(success=False, message="Failed to reset password"), 500
        
    @app.route("/setup_admin")
    def setup_admin():
        username = "admin"
        email = "admin@example.com"
        password = "Admin@123" 

        try:
            user = User.query.filter((User.username == username) | (User.email == email)).first()
            if not user:
                user = User(username=username, email=email, is_admin=True)
                user.set_password(password)
                db.session.add(user)
                db.session.commit()
                return jsonify({
                    "created": True,
                    "username": username,
                    "email": email,
                    "password": password
                }), 201
            else:
                user.is_admin = True
                user.set_password(password)
                db.session.commit()
                return jsonify({
                    "updated": True,
                    "username": user.username,
                    "email": user.email,
                    "password": password
                }), 200
        except Exception as e:
            db.session.rollback()
            app.logger.error("Admin setup error: %s", e)
            return jsonify({"error": "Failed to create admin"}), 500

    @app.route("/admin")
    @login_required
    def admin_dashboard():
        if not current_user.is_admin:
            abort(403)
        user_count = User.query.count()
        chat_count = Chat.query.count()
        message_count = Message.query.count()
        return render_template(
            "admin.html",
            user_count=user_count,
            chat_count=chat_count,
            message_count=message_count,
        )

    @app.route("/admin/users")
    @login_required
    def admin_users():
        if not current_user.is_admin:
            abort(403)
        users = User.query.all()
        return render_template("admin_users.html", users=users)

    @app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
    @login_required
    def delete_user(user_id: int):
        if not current_user.is_admin:
            abort(403)
        user = User.query.get_or_404(user_id)
        if user.id == current_user.id:
            flash("You cannot delete yourself.", "warning")
            return redirect(url_for("admin_users"))
        db.session.delete(user)
        db.session.commit()
        flash("User deleted.", "success")
        return redirect(url_for("admin_users"))

    @app.route("/chat/share/<int:chat_id>")
    @login_required
    def generate_share_link(chat_id: int):
        chat = Chat.query.get_or_404(chat_id)
        participant = ChatParticipant.query.filter_by(chat_id=chat_id, user_id=current_user.id).first()
        if not participant or participant.role != "owner":
            abort(403)

        token = uuid.uuid4().hex
        share = ShareLink(token=token, chat_id=chat.id)
        db.session.add(share)
        db.session.commit()

        share_url = url_for("view_shared_chat", token=token, _external=True)
        flash(f"Share this link: {share_url}", "info")
        return redirect(url_for("chat_view", chat_id=chat_id))


    @app.route("/chat/view/<token>")
    def view_shared_chat(token: str):
        share = ShareLink.query.filter_by(token=token).first_or_404()
        chat = Chat.query.options(joinedload(Chat.messages)).get_or_404(share.chat_id)
        messages = Message.query.filter_by(chat_id=chat.id).order_by(Message.id.asc()).all()

        return render_template(
            "chat_shared.html",
            chat=chat,
            messages=messages
        )

    @app.route('/feedback/like', methods=['POST'])
    @login_required
    def feedback_like():
        return jsonify(success=True, message="Thanks! Glad you liked this response 🙌")

    @app.route('/feedback/dislike', methods=['POST'])
    @login_required
    def feedback_dislike():
        data = request.get_json() or {}
        reasons = data.get("reasons", [])
        comments = data.get("comments", "")
        return jsonify(success=True, message="Feedback recorded. We'll use this to improve 🤝")

    @app.route("/chat/invite/<int:chat_id>")
    @login_required
    def invite_user(chat_id: int):
        chat = Chat.query.get_or_404(chat_id)
        participant = ChatParticipant.query.filter_by(chat_id=chat_id, user_id=current_user.id).first()
        if not participant or participant.role != "owner":
            abort(403)
        token = uuid.uuid4().hex
        invite_url = url_for("join_chat", chat_id=chat_id, token=token, _external=True)
        flash(f"Share this link to invite collaborators: {invite_url}", "info")
        return redirect(url_for("chat_view", chat_id=chat_id))

    @app.route("/chat/join/<int:chat_id>")
    @login_required
    def join_chat(chat_id: int):
        token = request.args.get("token")
        chat = Chat.query.get_or_404(chat_id)
        existing = ChatParticipant.query.filter_by(chat_id=chat_id, user_id=current_user.id).first()
        if not existing:
            participant = ChatParticipant(chat_id=chat_id, user_id=current_user.id, role="editor")
            db.session.add(participant)
            db.session.commit()
        return redirect(url_for("chat_view", chat_id=chat_id))

    @app.route("/contact", methods=["GET", "POST"])
    def contact():
        form = ContactForm()
        
        if form.validate_on_submit():
            try:
                msg = flask_mail.Message(
                subject=f"Contact Form: {form.query_type.data} from {form.name.data}",
                recipients=[app.config['ADMIN_EMAIL']],
                body=f"""
Name: {form.name.data}
Email: {form.email.data}
Query Type: {form.query_type.data}
Subscribe to updates: {'Yes' if form.subscribe.data else 'No'}

Message:
{form.message.data}
"""
            )
                mail.send(msg)
                flash('Your message has been sent successfully! We will get back to you soon.', 'success')
                return redirect(url_for('contact'))
                
            except Exception as e:
                app.logger.error(f"Failed to send contact email: {e}")
                flash('Sorry, there was an error sending your message. Please try again later.', 'danger')
        
        return render_template('contact.html', form=form)
    
    @app.route("/support")
    def support():
        return render_template("support.html")
    
    with app.app_context():
        try:
            db.create_all()
            app.logger.info("Database tables created successfully.")
        except Exception as e:
            app.logger.error("Error creating database tables: %s", e)

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True, host="0.0.0.0", use_reloader=False)
    # app.run(debug=True, host="0.0.0.0")