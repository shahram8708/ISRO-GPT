from datetime import datetime

from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

from extensions import db, login_manager


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    chats = db.relationship("Chat", back_populates="owner", cascade="all, delete-orphan")
    messages = db.relationship("Message", back_populates="user", cascade="all, delete-orphan")
    participants = db.relationship("ChatParticipant", back_populates="user", cascade="all, delete-orphan")

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def __repr__(self) -> str:
        return f"<User {self.username}>"


class Chat(db.Model):
    __tablename__ = "chats"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    owner = db.relationship("User", back_populates="chats")
    messages = db.relationship("Message", back_populates="chat", cascade="all, delete-orphan")
    participants = db.relationship("ChatParticipant", back_populates="chat", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Chat {self.name}>"


class Message(db.Model):
    __tablename__ = "messages"

    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey("chats.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    role = db.Column(db.String(20), nullable=False) 
    content = db.Column(db.Text, nullable=True)
    file_path = db.Column(db.String(512), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    chat = db.relationship("Chat", back_populates="messages")
    user = db.relationship("User", back_populates="messages")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "chat_id": self.chat_id,
            "user_id": self.user_id,
            "role": self.role,
            "content": self.content,
            "file_path": self.file_path,
            "created_at": self.created_at.isoformat(),
        }

    def __repr__(self) -> str:
        return f"<Message {self.role} {'with file' if self.file_path else ''}>"


class MosdacUpdate(db.Model):
    __tablename__ = "mosdac_updates"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(512), nullable=False)
    summary = db.Column(db.Text, nullable=True)
    link = db.Column(db.String(1024), nullable=False)
    position = db.Column(db.Integer, nullable=False, default=1)
    published_at = db.Column(db.String(64), nullable=True)
    retrieved_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "summary": self.summary,
            "link": self.link,
            "position": self.position,
            "published_at": self.published_at,
        }


class ShareLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, nullable=False)
    chat_id = db.Column(db.Integer, db.ForeignKey('chats.id'), nullable=False) 
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    chat = db.relationship("Chat", backref="share_links")

class ChatParticipant(db.Model):
    __tablename__ = "chat_participants"

    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey("chats.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    role = db.Column(db.String(20), default="owner") 
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)

    chat = db.relationship("Chat", back_populates="participants")
    user = db.relationship("User", back_populates="participants")

    def __repr__(self) -> str:
        return f"<ChatParticipant user={self.user_id} chat={self.chat_id} role={self.role}>"


@login_manager.user_loader
def load_user(user_id: str):
    return User.query.get(int(user_id))