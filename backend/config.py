import os
from datetime import timedelta

def _get_env(name, default=None, required=False):
    """Helper to fetch env vars; fail if `required` and missing."""
    val = os.getenv(name, default)
    if required and not val:
        raise RuntimeError(f"{name} environment variable must be set!")
    return val

def _get_secret(name, file_env):
    """Prefer env var, then file; strip newline."""
    val = os.getenv(name)
    if val:
        return val
    path = os.getenv(file_env)
    if path and os.path.isfile(path):
        return open(path, "r").read().strip()
    return None

#! THIS FOR DEVELOPMENT MODE
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
    DB_HOST = os.getenv("DB_HOST")
    DB_USER = os.getenv("DB_USER")
    DB_PASSWORD = os.getenv("DB_PASSWORD")
    DB_NAME = os.getenv("DB_NAME")

    # reCAPTCHA keys (optional)
    RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY")
    RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")

    # --- Debug / SQL Logging ------------------
    DEBUG = False
    SQLALCHEMY_ECHO = False


class DevelopmentConfig(BaseConfig):
    # local fallbacks for “works out of the box”
    DB_HOST     = os.getenv("DB_HOST",     "localhost")
    DB_USER     = os.getenv("DB_USER",     "root")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "")
    DB_NAME     = os.getenv("DB_NAME",     "rbac")

    SQLALCHEMY_DATABASE_URI = (
        f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"
    )
    DEBUG = True
    SQLALCHEMY_ECHO = True


class ProductionConfig(BaseConfig):
    # --- Force all secrets to be set -------------------------------------------
    SECRET_KEY         = _get_env("FLASK_SECRET_KEY", required=True)
    
    # Mail must be configured in env/secrets
    MAIL_SERVER         = _get_env("MAIL_SERVER",         required=True)
    MAIL_PORT           = int(_get_env("MAIL_PORT",       required=True))
    MAIL_USE_TLS        = _get_env("MAIL_USE_TLS",        required=True).lower() == "true"
    MAIL_USERNAME       = _get_env("MAIL_USERNAME",       required=True)

    MAIL_PASSWORD = _get_secret("MAIL_PASSWORD", "MAIL_PASSWORD_FILE")
    if not MAIL_PASSWORD:
        raise RuntimeError("MAIL_PASSWORD or MAIL_PASSWORD_FILE must be set!")
    
    MAIL_DEFAULT_SENDER = _get_env("MAIL_DEFAULT_SENDER",required=True)

    raw = os.getenv("DB_PASSWORD") or os.getenv("DB_PASSWORD_FILE")
    if raw and os.path.isfile(raw):
        DB_PASSWORD = open(raw).read().strip()
    else:
        DB_PASSWORD = _get_env("DB_PASSWORD", required=True)

    DB_HOST     = _get_env("DB_HOST",     required=True)
    DB_USER     = _get_env("DB_USER",     required=True)
    DB_NAME     = _get_env("DB_NAME",     required=True)

    # --- SQLAlchemy URI (build from the required DB_* vars) ------------------
    SQLALCHEMY_DATABASE_URI = (
        f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"
    )

    # reCAPTCHA configuration
    RECAPTCHA_SITE_KEY = _get_secret("RECAPTCHA_SITE_KEY", "RECAPTCHA_SITE_KEY_FILE") \
                        or _get_env("RECAPTCHA_SITE_KEY", required=True)
    RECAPTCHA_SECRET_KEY = _get_secret("RECAPTCHA_SECRET_KEY", "RECAPTCHA_SECRET_KEY_FILE") \
                           or _get_env("RECAPTCHA_SECRET_KEY", required=True)

    # --- Always off in prod ---------------------------------------------------
    DEBUG           = False
    SQLALCHEMY_ECHO = False
