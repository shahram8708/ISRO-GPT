import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "ISRO-GPT-6708@")
    REMEMBER_COOKIE_DURATION = timedelta(days=30)  
    PERMANENT_SESSION_LIFETIME = timedelta(days=30)
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(os.path.dirname(__file__), 'isro-gpt.db')}"
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

    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'false').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', 'multimosaic.help@gmail.com')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', 'eurr xxsx brxz anrz')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'multimosaic.help@gmail.com')
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'multimosaic.help@gmail.com')

    TWILIO_ACCOUNT_SID = "ACe22c004acbbbef75cec10cd919dbea35"
    TWILIO_AUTH_TOKEN = "7e9ec87efd5a3d18d7f6d4e673b62632"
    TWILIO_WHATSAPP_NUMBER = "+17153175873"
    WHATSAPP_MAX_WORDS = int(os.environ.get("WHATSAPP_MAX_WORDS", 350))
    WHATSAPP_MAX_CHARACTERS = int(os.environ.get("WHATSAPP_MAX_CHARACTERS", 1600))
