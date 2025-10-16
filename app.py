from __future__ import annotations
from flask import current_app

import os
import json
import uuid
import secrets
import re
from typing import Dict, List, Optional, Tuple
import base64
import mimetypes
import requests
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
from models import User, Chat, Message, ChatParticipant, ShareLink, MosdacUpdate
from rag_pipeline import RAGPipeline, RAGPipelineError

REPLACEMENTS = {
    "google": "ISRO-GPT",
    "gemini": "ISRO-GPT",
    "bard": "ISRO-GPT",
}


def replace_words(text: str) -> str:
    for word, replacement in REPLACEMENTS.items():
        text = text.replace(word, replacement)
        text = text.replace(word.capitalize(), replacement.capitalize())
        text = text.replace(word.upper(), replacement.upper())
    return text
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException
from twilio.twiml.messaging_response import MessagingResponse

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

    twilio_client: Optional[Client] = None
    account_sid = app.config.get("TWILIO_ACCOUNT_SID")
    auth_token = app.config.get("TWILIO_AUTH_TOKEN")
    if account_sid and auth_token:
        try:
            twilio_client = Client(account_sid, auth_token)
            app.extensions["twilio_client"] = twilio_client
            app.logger.info("Twilio client initialized for WhatsApp messaging.")
        except Exception as exc:
            twilio_client = None
            app.logger.error("Failed to initialize Twilio client: %s", exc, exc_info=True)
    else:
        app.logger.warning("Twilio credentials not provided; WhatsApp integration disabled.")

    login_manager.login_view = "login"
    login_manager.login_message_category = "info"

    try:
        rag_pipeline = RAGPipeline(app.config, logger=app.logger)
        app.extensions["rag_pipeline"] = rag_pipeline
        app.logger.info("RAG pipeline initialised successfully.")
    except Exception as exc:
        app.logger.error("Failed to initialise RAG pipeline: %s", exc, exc_info=True)
        app.extensions["rag_pipeline"] = None

    def persist_bytes_to_uploads(file_bytes: bytes, original_filename: Optional[str], mime_type: Optional[str]) -> str:
        if not file_bytes:
            raise ValueError("Attachment payload is empty.")

        safe_name = secure_filename(original_filename or "whatsapp_upload") or "whatsapp_upload"
        base_name, ext = os.path.splitext(safe_name)
        if not ext and mime_type:
            guessed_ext = mimetypes.guess_extension(mime_type) or ""
            ext = guessed_ext
        if not ext:
            ext = ""
        unique_name = f"{uuid.uuid4().hex}_{base_name}{ext}"
        abs_path = os.path.join(app.config["UPLOAD_FOLDER"], unique_name)

        try:
            with open(abs_path, "wb") as destination:
                destination.write(file_bytes)
        except Exception as exc:
            app.logger.error("Failed to persist attachment %s: %s", unique_name, exc, exc_info=True)
            raise

        return unique_name

    def register_local_attachment(stored_name: str, mime_type: Optional[str]) -> Tuple[Dict[str, str], str]:
        abs_path = os.path.join(app.config["UPLOAD_FOLDER"], stored_name)
        resolved_mime = mime_type or mimetypes.guess_type(abs_path)[0] or "application/octet-stream"
        ext = stored_name.rsplit(".", 1)[1].lower() if "." in stored_name else ""
        extracted_text = ""

        if ext == "pdf":
            try:
                with pdfplumber.open(abs_path) as pdf:
                    for page_num, page in enumerate(pdf.pages, start=1):
                        page_text = page.extract_text() or ""
                        if page_text:
                            extracted_text += f"\n\n--- Page {page_num} ---\n" + page_text
            except Exception as exc:
                app.logger.error("PDF extraction error for %s: %s", stored_name, exc, exc_info=True)

        attachment_meta: Dict[str, str] = {
            "abs_path": abs_path,
            "mime_type": resolved_mime,
            "name": stored_name,
            "ext": ext,
        }
        return attachment_meta, extracted_text

    def count_words(text: str) -> int:
        if not text:
            return 0
        return len(re.findall(r"\b[\w'-]+\b", text))

    def sanitize_whatsapp_markdown(text: str) -> str:
        if not text:
            return ""

        sanitized = text.replace("\r\n", "\n")

        sanitized = re.sub(r"```(.*?)```", lambda m: m.group(1).strip(), sanitized, flags=re.DOTALL)
        sanitized = re.sub(r"`([^`]+)`", r"\1", sanitized)

        sanitized = re.sub(
            r"^\s{0,3}#{1,6}\s*(.+)$",
            lambda m: f"*{m.group(1).strip()}*",
            sanitized,
            flags=re.MULTILINE,
        )

        sanitized = re.sub(r"^\s{0,3}>\s*", "", sanitized, flags=re.MULTILINE)
        sanitized = re.sub(r"^\s*[-:|]{2,}\s*$", "", sanitized, flags=re.MULTILINE)

        sanitized = re.sub(
            r"^\s*\|.+\|\s*$",
            lambda m: " ".join(cell.strip() for cell in m.group(0).split("|") if cell.strip()),
            sanitized,
            flags=re.MULTILINE,
        )

        sanitized = re.sub(r"\*\*(.+?)\*\*", r"*\1*", sanitized)
        sanitized = re.sub(r"__(.+?)__", r"_\1_", sanitized)
        sanitized = re.sub(r"~~(.+?)~~", r"~\1~", sanitized)

        sanitized = re.sub(r"^\s*[\*•]\s+", "- ", sanitized, flags=re.MULTILINE)
        sanitized = re.sub(r"^\s*-\s{2,}", "- ", sanitized, flags=re.MULTILINE)

        sanitized = re.sub(r"[ \t]{2,}", " ", sanitized)
        sanitized = re.sub(r"\n{3,}", "\n\n", sanitized)

        return sanitized.strip()

    def generate_ai_response(
        chat_id: int,
        prompt: str,
        attachments: Optional[List[dict]] = None,
    ) -> Tuple[str, List[Dict[str, str]]]:
        history_messages = (
            Message.query
            .filter(Message.chat_id == chat_id)
            .order_by(Message.id.desc())
            .limit(6)
            .all()[::-1]
        )

        history_lines: List[str] = []
        for msg in history_messages:
            if msg.role not in {"user", "ai"}:
                continue
            if not msg.content:
                continue
            role_label = "User" if msg.role == "user" else "Assistant"
            history_lines.append(f"{role_label}: {msg.content.strip()}")

        history_text = "\n".join(history_lines[-6:]) if history_lines else None

        pipeline: Optional[RAGPipeline] = current_app.extensions.get("rag_pipeline")
        if not pipeline:
            current_app.logger.error("RAG pipeline is not initialised; returning fallback message.")
            return "Search pipeline is unavailable. Please try again later.", []

        question = (prompt or "").strip()
        if not question:
            question = "Provide a helpful response to the user based on the previous conversation."

        try:
            result = pipeline.run(question, history=history_text)
        except RAGPipelineError as exc:
            current_app.logger.error(
                "RAG pipeline error for chat %s: %s", chat_id, exc, exc_info=True
            )
            return "Unable to fetch search results. Please try again later.", []

        answer = result.answer.strip() or "No response."
        return answer, result.sources

    def fetch_mosdac_updates_via_rag() -> List[dict]:
        pipeline: Optional[RAGPipeline] = current_app.extensions.get("rag_pipeline")
        if not pipeline:
            raise RuntimeError("RAG pipeline is not configured.")

        rag_query = (
            "site:https://www.mosdac.gov.in latest updates announcements or notices from MOSDAC. "
            "Return a JSON array with exactly four objects ordered newest to oldest. Each object must have keys "
            "title (string), summary (string under 280 characters), link (URL), and published_at (string, allow empty). "
            "Respond with JSON only."
        )

        try:
            result = pipeline.run(rag_query)
        except RAGPipelineError as exc:
            raise RuntimeError("Unable to fetch MOSDAC updates via RAG.") from exc

        raw_text = result.answer.strip()
        if not raw_text:
            raise ValueError("RAG pipeline returned an empty response for MOSDAC updates.")

        cleaned = raw_text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.lstrip("`")
            if cleaned.lower().startswith("json"):
                cleaned = cleaned[4:]
            cleaned = cleaned.strip("`").strip()

        try:
            payload = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Unable to parse MOSDAC updates JSON: {exc}") from exc

        if not isinstance(payload, list):
            raise ValueError("MOSDAC updates payload must be a list of updates")

        normalized: List[dict] = []
        for idx, item in enumerate(payload[:4], start=1):
            if not isinstance(item, dict):
                continue
            title = (item.get("title") or "").strip()
            link = (item.get("link") or "").strip()
            if not title or not link:
                continue
            summary = (item.get("summary") or "").strip()
            published_at = (item.get("published_at") or "").strip()
            normalized.append({
                "title": title,
                "summary": summary,
                "link": link,
                "published_at": published_at,
                "position": idx,
            })

        if len(normalized) < 4:
            raise ValueError("Search pipeline returned fewer than four MOSDAC updates")

        return normalized

    def replace_mosdac_updates(updates: List[dict]) -> List[MosdacUpdate]:
        db.session.query(MosdacUpdate).delete(synchronize_session=False)
        records: List[MosdacUpdate] = []
        for update in updates[:4]:
            record = MosdacUpdate(
                title=update["title"],
                summary=update.get("summary"),
                link=update["link"],
                position=update.get("position", len(records) + 1),
                published_at=update.get("published_at"),
            )
            db.session.add(record)
            records.append(record)

        db.session.commit()
        return records

    def process_chat_interaction(
        chat: Chat,
        sender_user_id: Optional[int],
        message_text: str,
        attachments: List[Dict[str, str]],
        extracted_text: str = "",
        ai_directives: Optional[List[str]] = None,
    ) -> Tuple[Dict[str, object], Dict[str, object], str, List[Dict[str, str]]]:
        if chat is None:
            raise ValueError("Chat context is required to process messages.")

        safe_message_text = (message_text or "").strip()
        stored_names = [att.get("name") for att in attachments if att.get("name")]
        file_reference = ",".join(stored_names) if stored_names else None

        try:
            user_message = Message(
                chat_id=chat.id,
                user_id=sender_user_id,
                role="user",
                content=safe_message_text if safe_message_text else None,
                file_path=file_reference,
            )
            db.session.add(user_message)
            db.session.flush()

            effective_prompt = safe_message_text
            if extracted_text:
                if effective_prompt:
                    effective_prompt = f"{effective_prompt}\n\n{extracted_text}".strip()
                else:
                    effective_prompt = extracted_text.strip()

            if ai_directives:
                directive_text = "\n".join(dir_line.strip() for dir_line in ai_directives if dir_line.strip())
                if directive_text:
                    effective_prompt = (
                        f"{directive_text}\n\n{effective_prompt}" if effective_prompt else directive_text
                    )

            ai_reply_text, sources = generate_ai_response(
                chat.id, effective_prompt, attachments=attachments
            )
            ai_reply_text = replace_words(ai_reply_text)

            source_lines: List[str] = []
            if sources:
                for idx, src in enumerate(sources, start=1):
                    title = (src.get("title") or src.get("url") or f"Source {idx}").strip()
                    url = (src.get("url") or "").strip()
                    if url:
                        source_lines.append(f"{idx}. {title} - {url}")
                    else:
                        source_lines.append(f"{idx}. {title}")

            final_reply = ai_reply_text
            if source_lines:
                final_reply = f"{ai_reply_text}\n\nSources:\n" + "\n".join(source_lines)

            ai_message = Message(
                chat_id=chat.id,
                role="ai",
                content=final_reply,
            )
            db.session.add(ai_message)
            db.session.commit()

            ai_payload = ai_message.to_dict()
            if sources:
                ai_payload["sources"] = sources

            return user_message.to_dict(), ai_payload, final_reply, sources
        except Exception as exc:
            db.session.rollback()
            app.logger.error("Failed to process chat interaction: %s", exc, exc_info=True)
            raise

    def get_or_create_whatsapp_resources(wa_number: str) -> Tuple[User, Chat]:
        normalized = wa_number.replace("whatsapp:", "")
        digits = "".join(ch for ch in normalized if ch.isdigit())
        username = f"wa_{digits}" if digits else f"wa_{uuid.uuid4().hex[:8]}"
        email = f"{username}@whatsapp.local"

        user = User.query.filter_by(email=email).first()
        created_user = False
        if not user:
            user = User(username=username[:80], email=email)
            user.set_password(secrets.token_urlsafe(16))
            db.session.add(user)
            db.session.flush()
            created_user = True

        chat_name = f"WhatsApp {normalized}"
        chat = Chat.query.filter_by(owner_id=user.id, name=chat_name).first()
        if not chat:
            chat = Chat(name=chat_name, owner_id=user.id)
            db.session.add(chat)
            db.session.flush()

        participant = ChatParticipant.query.filter_by(chat_id=chat.id, user_id=user.id).first()
        if not participant:
            participant = ChatParticipant(chat_id=chat.id, user_id=user.id, role="owner")
            db.session.add(participant)

        if created_user:
            app.logger.info("Created WhatsApp virtual user %s for %s", user.username, wa_number)

        return user, chat

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
        mosdac_updates = (
            MosdacUpdate.query.order_by(MosdacUpdate.position.asc(), MosdacUpdate.id.asc()).all()
        )
        return render_template("dashboard.html", chats=chats, mosdac_updates=mosdac_updates)

    @app.route("/api/mosdac/updates", methods=["GET"])
    def api_mosdac_updates():
        updates = (
            MosdacUpdate.query.order_by(MosdacUpdate.position.asc(), MosdacUpdate.id.asc()).all()
        )
        return jsonify({"updates": [update.to_dict() for update in updates]})

    @app.route("/api/mosdac/refresh", methods=["POST"])
    def api_mosdac_refresh_updates():
        try:
            normalized = fetch_mosdac_updates_via_rag()
            records = replace_mosdac_updates(normalized)
        except Exception as exc:
            db.session.rollback()
            current_app.logger.error("Failed to refresh MOSDAC updates: %s", exc, exc_info=True)
            return jsonify({"error": str(exc)}), 500

        return jsonify({"updates": [record.to_dict() for record in records]})

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
        message_text = (request.form.get("message") or "").strip()
        files = request.files.getlist("files") if "files" in request.files else []

        if not message_text and not files:
            return jsonify({"error": "Message cannot be empty."}), 400

        attachments: List[Dict[str, str]] = []
        extracted_segments: List[str] = []

        for file in files:
            if file.filename == "":
                continue
            if not allowed_file(file.filename):
                return jsonify({"error": f"Unsupported file type: {file.filename}"}), 400

            try:
                file_bytes = file.read()
            except Exception as exc:
                app.logger.error("Failed to read uploaded file %s: %s", file.filename, exc, exc_info=True)
                return jsonify({"error": f"Failed to read file {file.filename}."}), 400

            if not file_bytes:
                continue

            try:
                stored_name = persist_bytes_to_uploads(file_bytes, file.filename, file.mimetype)
                attachment_meta, extracted_text_segment = register_local_attachment(stored_name, file.mimetype)
                attachments.append(attachment_meta)
                if extracted_text_segment:
                    extracted_segments.append(extracted_text_segment)
            except ValueError as exc:
                return jsonify({"error": str(exc)}), 400
            except Exception as exc:
                app.logger.error("Failed to persist uploaded file %s: %s", file.filename, exc, exc_info=True)
                return jsonify({"error": f"Failed to store file {file.filename}."}), 500

        combined_extracted_text = "".join(extracted_segments)

        try:
            user_payload, ai_payload, _, sources = process_chat_interaction(
                chat,
                current_user.id,
                message_text,
                attachments,
                combined_extracted_text,
            )
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception:
            return jsonify({"error": "Failed to send message."}), 500

        response_payload = {
            "messages": [user_payload, ai_payload],
        }
        if sources:
            response_payload["sources"] = sources

        return jsonify(response_payload)

    @app.route("/integrations/whatsapp", methods=["POST"])
    @csrf.exempt
    def whatsapp_webhook():
        twilio_cfg_missing = not (app.config.get("TWILIO_ACCOUNT_SID") and app.config.get("TWILIO_AUTH_TOKEN") and app.config.get("TWILIO_WHATSAPP_NUMBER"))
        messaging_response = MessagingResponse()

        if twilio_cfg_missing:
            app.logger.error("WhatsApp webhook invoked but Twilio credentials are missing.")
            messaging_response.message("WhatsApp integration is not configured. Please contact support.")
            return str(messaging_response), 503, {"Content-Type": "application/xml"}

        from_number = request.form.get("From", "").strip()
        body = request.form.get("Body", "")

        if not from_number.startswith("whatsapp:"):
            app.logger.warning("Received WhatsApp webhook with invalid sender: %s", from_number)
            messaging_response.message("We could not identify your WhatsApp number. Please try again.")
            return str(messaging_response), 400, {"Content-Type": "application/xml"}

        try:
            whatsapp_user, chat = get_or_create_whatsapp_resources(from_number)
        except Exception as exc:
            app.logger.error("Failed to prepare WhatsApp resources: %s", exc, exc_info=True)
            db.session.rollback()
            messaging_response.message("We could not start your chat session. Please try again later.")
            return str(messaging_response), 500, {"Content-Type": "application/xml"}

        media_count_value = request.form.get("NumMedia") or request.form.get("MediaCount") or "0"
        attachments: List[Dict[str, str]] = []
        extracted_segments: List[str] = []

        try:
            media_count = int(media_count_value)
        except (TypeError, ValueError):
            media_count = 0

        account_sid = app.config.get("TWILIO_ACCOUNT_SID")
        auth_token = app.config.get("TWILIO_AUTH_TOKEN")

        for idx in range(media_count):
            media_url = request.form.get(f"MediaUrl{idx}")
            if not media_url:
                continue
            mime_type = request.form.get(f"MediaContentType{idx}")
            original_filename = request.form.get(f"MediaFilename{idx}") or f"whatsapp_media_{idx}"

            try:
                media_response = requests.get(media_url, auth=(account_sid, auth_token), timeout=30)
                media_response.raise_for_status()
            except requests.RequestException as exc:
                app.logger.error("Failed to download WhatsApp media %s: %s", media_url, exc, exc_info=True)
                continue

            try:
                stored_name = persist_bytes_to_uploads(media_response.content, original_filename, mime_type)
                attachment_meta, extracted_text_segment = register_local_attachment(stored_name, mime_type)
                attachments.append(attachment_meta)
                if extracted_text_segment:
                    extracted_segments.append(extracted_text_segment)
            except ValueError as exc:
                app.logger.warning("Skipping empty media payload from %s: %s", from_number, exc)
                continue
            except Exception as exc:
                app.logger.error("Failed to persist WhatsApp media from %s: %s", media_url, exc, exc_info=True)
                continue

        if not body and not attachments:
            db.session.rollback()
            messaging_response.message("We did not receive any content. Please send a message or attachment.")
            return str(messaging_response), 200, {"Content-Type": "application/xml"}

        combined_extracted_text = "".join(extracted_segments)

        max_words = int(app.config.get("WHATSAPP_MAX_WORDS", 350) or 0)
        max_chars = int(app.config.get("WHATSAPP_MAX_CHARACTERS", 1600) or 0)
        if max_words <= 0:
            max_words = 350
        if max_chars <= 0:
            max_chars = 1600
        whatsapp_directives = [
            f"IMPORTANT: Your reply must be a direct answer to the user query in no more than {max_words} words (approx {max_chars} characters).",
            "Do NOT explain the limits or talk about word count. Just follow them silently.",
            "Use only WhatsApp-supported markdown for formatting: *bold*, _italic_, ~strikethrough~, - bullets, or numbered lists.",
            "Do NOT include unsupported markdown (headings, tables, code blocks).",
            "Keep the reply concise, user-friendly, and error-free. If the user asks for something long, summarize instead of exceeding the limit.",
        ]
        try:
            _, ai_payload, ai_reply, _sources = process_chat_interaction(
                chat,
                whatsapp_user.id,
                body,
                attachments,
                combined_extracted_text,
                ai_directives=whatsapp_directives,
            )
        except Exception as exc:
            app.logger.error("Failed to generate AI reply for WhatsApp user %s: %s", from_number, exc, exc_info=True)
            messaging_response.message("We hit an error processing your message. Please try again.")
            return str(messaging_response), 500, {"Content-Type": "application/xml"}

        word_count = count_words(ai_reply)
        char_count = len(ai_reply or "")
        if max_words and word_count > max_words:
            app.logger.warning(
                "WhatsApp AI reply exceeded word limit (limit_words=%s, actual_words=%s, user_body=%s)",
                max_words,
                word_count,
                body,
            )
        if max_chars and char_count > max_chars:
            app.logger.warning(
                "WhatsApp AI reply exceeded character limit (limit_chars=%s, actual_chars=%s, user_body=%s)",
                max_chars,
                char_count,
                body,
            )

        sanitized_reply = sanitize_whatsapp_markdown(ai_reply)
        if not sanitized_reply.strip():
            sanitized_reply = (ai_reply or "").strip()

        outgoing = messaging_response.message()
        outgoing.body(sanitized_reply)

        return str(messaging_response), 200, {"Content-Type": "application/xml"}

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
        username = "ISRO GPT"
        email = "gpt@isro.com"
        password = "ISRO-GPT@6708" 

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
    
    @app.route("/terms")
    def terms():
        return render_template("terms.html")

    @app.route("/about")
    def about():
        return render_template("about.html")

    @app.route("/privacy")
    def privacy():
        return render_template("privacy.html")

    with app.app_context():
        try:
            db.create_all()
            app.logger.info("Database tables created successfully.")
        except Exception as e:
            app.logger.error("Error creating database tables: %s", e)

    @app.route("/api/mosdac/refresh", methods=["POST"])
    @csrf.exempt
    def api_refresh_mosdac():
        try:
            updates_payload = fetch_mosdac_updates_via_rag()
            records = replace_mosdac_updates(updates_payload)
            return jsonify({
                "updates": [record.to_dict() for record in records],
                "count": len(records),
            })
        except Exception as exc:
            db.session.rollback()
            current_app.logger.error("Failed to refresh MOSDAC updates: %s", exc, exc_info=True)
            return jsonify({
                "error": "Failed to refresh MOSDAC updates",
                "details": str(exc),
            }), 500
        
    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True, host="0.0.0.0", use_reloader=False)
    # app.run(debug=True, host="0.0.0.0")