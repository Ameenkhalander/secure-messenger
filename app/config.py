import os
from datetime import timedelta


def _bool(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _csv(name: str) -> list[str]:
    return [v.strip() for v in os.environ.get(name, "").split(",") if v.strip()]


class Config:
    ENV_NAME = "development"
    SECRET_KEY = os.environ.get("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL")  # defaults to instance/messenger.db
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}

    # cookies / sessions
    SESSION_COOKIE_NAME = "sm_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _bool("COOKIE_SECURE", False)
    SESSION_ABSOLUTE_LIFETIME = timedelta(hours=int(os.environ.get("SESSION_HOURS", "12")))
    SESSION_IDLE_TIMEOUT = timedelta(minutes=int(os.environ.get("SESSION_IDLE_MINUTES", "60")))
    PERMANENT_SESSION_LIFETIME = SESSION_ABSOLUTE_LIFETIME

    # request limits
    MAX_CONTENT_LENGTH = 256 * 1024
    MAX_DEVICES_PER_USER = 10
    MAX_GROUP_MEMBERS = 50
    MAX_MESSAGE_SKEW_SECONDS = 300  # replay window for signed timestamps

    # password hashing (Argon2id)
    ARGON2_MEMORY_KIB = int(os.environ.get("ARGON2_MEMORY_KIB", "65536"))
    ARGON2_ITERATIONS = int(os.environ.get("ARGON2_ITERATIONS", "3"))
    ARGON2_LANES = int(os.environ.get("ARGON2_LANES", "4"))
    LOCKOUT_THRESHOLD = 5
    LOCKOUT_MINUTES = 15
    PASSWORD_RESET_MINUTES = 30

    # rate limiting
    RATELIMIT_ENABLED = _bool("RATELIMIT_ENABLED", True)
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_HEADERS_ENABLED = True

    # misc
    CSRF_ENABLED = True
    TRUSTED_PROXY_COUNT = int(os.environ.get("TRUSTED_PROXY_COUNT", "0"))
    SOCKETIO_CORS_ORIGINS = _csv("SOCKETIO_CORS_ORIGINS") or None  # None = same-origin only
    SOCKETIO_ASYNC_MODE = os.environ.get("SOCKETIO_ASYNC_MODE", "threading")
    HSTS_ENABLED = _bool("HSTS_ENABLED", False)

    # mail (password reset). Without SMTP_HOST the link is written to instance/outbox.log
    SMTP_HOST = os.environ.get("SMTP_HOST")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
    SMTP_USER = os.environ.get("SMTP_USER")
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
    MAIL_FROM = os.environ.get("MAIL_FROM", "no-reply@localhost")
    PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "http://localhost:5000")


class DevelopmentConfig(Config):
    DEBUG = False  # never enable the Werkzeug debugger on a network-reachable port


class ProductionConfig(Config):
    ENV_NAME = "production"
    SESSION_COOKIE_SECURE = _bool("COOKIE_SECURE", True)  # set COOKIE_SECURE=false to test over plain http
    HSTS_ENABLED = _bool("HSTS_ENABLED", True)


class TestingConfig(Config):
    ENV_NAME = "testing"
    TESTING = True
    SECRET_KEY = "testing-secret-key-not-for-production"
    RATELIMIT_ENABLED = False
    SESSION_COOKIE_SECURE = False
    ARGON2_MEMORY_KIB = 1024
    ARGON2_ITERATIONS = 1
    ARGON2_LANES = 1


_CONFIGS = {"development": DevelopmentConfig, "production": ProductionConfig, "testing": TestingConfig}


def get_config(name: str | None = None):
    return _CONFIGS[name or os.environ.get("APP_ENV", "development")]
