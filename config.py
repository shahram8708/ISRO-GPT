import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "ISRO-GPT-6708@")
    REMEMBER_COOKIE_DURATION = timedelta(days=30)  
    PERMANENT_SESSION_LIFETIME = timedelta(days=30)
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(os.path.dirname(__file__), 'app.db')}"
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    UPLOAD_FOLDER = os.environ.get(
        "UPLOAD_FOLDER",
        os.path.join(os.path.dirname(__file__), "static", "uploads"),
    )
    
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", 16 * 1024 * 1024))
    
    ALLOWED_EXTENSIONS = {'png','jpg','jpeg','gif','webp','bmp','svg','pdf'}

    GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY", "AIzaSyC1dSEI8aENjszrP9IcqZYX561QV8ASHa0")

    MESSAGES_PER_PAGE = int(os.environ.get("MESSAGES_PER_PAGE", 50))
