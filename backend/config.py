import os
from datetime import datetime, date, timedelta
from app import secret

class BaseConfig:
    # General Flask Config
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "ssd-team-22-project-dev")

    # Session and Security
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=15)
    SESSION_REFRESH_EACH_REQUEST = True

    # Flask-Mail config (email service)
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.example.com')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'true').lower() == 'true'
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER')

    # Database config
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_USER = os.getenv("DB_USER", "root")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "admin")
    DB_NAME = os.getenv("DB_NAME", "rbac")

    # reCAPTCHA keys (optional)
    RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY")
    RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")

    # Debug
    DEBUG = False
    SQLALCHEMY_ECHO = False


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    SQLALCHEMY_ECHO = True


class ProductionConfig(BaseConfig):
    # Require a real secret key in production, or fail fast
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY")
    MAIL_PASSWORD = secret("MAIL_PASSWORD")
    if not SECRET_KEY:
        raise RuntimeError("FLASK_SECRET_KEY environment variable must be set in production!")

    DEBUG = False
    SQLALCHEMY_ECHO = False
