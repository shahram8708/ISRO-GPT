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

    SEARCH_MAX_RESULTS = int(os.environ.get("SEARCH_MAX_RESULTS", 8))
    SEARCH_SAFE_MODE = os.environ.get("SEARCH_SAFE_MODE", "moderate")
    SEARCH_REGION = os.environ.get("SEARCH_REGION", "wt-wt")
    SEARCH_ALLOWED_LANGS = os.environ.get("SEARCH_ALLOWED_LANGS", "en")
    SEARCH_CACHE_SIZE = int(os.environ.get("SEARCH_CACHE_SIZE", 32))

    CONTENT_FETCH_TIMEOUT = float(os.environ.get("CONTENT_FETCH_TIMEOUT", 12))
    CONTENT_FETCH_USER_AGENT = os.environ.get("CONTENT_FETCH_USER_AGENT", "ISRO-GPT-RAG/1.0")
    RAG_MAX_CONTENT_CHARS = int(os.environ.get("RAG_MAX_CONTENT_CHARS", 9000))
    RAG_CHUNK_TOKENS = int(os.environ.get("RAG_CHUNK_TOKENS", 360))
    RAG_CHUNK_OVERLAP_TOKENS = int(os.environ.get("RAG_CHUNK_OVERLAP_TOKENS", 40))
    RAG_TOP_K = int(os.environ.get("RAG_TOP_K", 5))
    RAG_MAX_CONTEXT_PASSAGES = int(os.environ.get("RAG_MAX_CONTEXT_PASSAGES", 5))
    RAG_CONTENT_CACHE_SIZE = int(os.environ.get("RAG_CONTENT_CACHE_SIZE", 32))
    RAG_ANSWER_CACHE_SIZE = int(os.environ.get("RAG_ANSWER_CACHE_SIZE", 32))

    LLM_BACKEND = os.environ.get("LLM_BACKEND", "llama_cpp")
    DEFAULT_MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "mistral-7b-instruct.Q4_K_M.gguf")

    LLAMA_CPP_MODEL_PATH = os.environ.get("LLAMA_CPP_MODEL_PATH", DEFAULT_MODEL_PATH)
    LLAMA_CPP_N_CTX = int(os.environ.get("LLAMA_CPP_N_CTX", 4096))
    LLAMA_CPP_N_THREADS = os.environ.get("LLAMA_CPP_N_THREADS")
    OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
    OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "")
    LLM_TEMPERATURE = float(os.environ.get("LLM_TEMPERATURE", 0.2))
    LLM_MAX_OUTPUT_TOKENS = int(os.environ.get("LLM_MAX_OUTPUT_TOKENS", 512))
    LLM_REQUEST_TIMEOUT = float(os.environ.get("LLM_REQUEST_TIMEOUT", 120))
    LLM_SYSTEM_PROMPT = os.environ.get("LLM_SYSTEM_PROMPT")
    LLM_MODEL_URL = os.environ.get(
        "LLM_MODEL_URL",
        "https://huggingface.co/TheBloke/Mistral-7B-Instruct-v0.2-GGUF/resolve/main/mistral-7b-instruct-v0.2.Q4_K_M.gguf?download=1",
    )
    LLM_MODEL_SHA256 = os.environ.get("LLM_MODEL_SHA256")

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
