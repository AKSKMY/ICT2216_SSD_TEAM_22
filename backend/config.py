import os

class BaseConfig:
    # Default secret key for dev; override in production with strong secret via env var
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "ssd-team-22-project-dev")

    # Database connection defaults
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_USER = os.getenv("DB_USER", "root")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "admin")
    DB_NAME = os.getenv("DB_NAME", "rbac")

    DEBUG = False
    SQLALCHEMY_ECHO = False  # Optional if using SQLAlchemy


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    SQLALCHEMY_ECHO = True


class ProductionConfig(BaseConfig):
    # Require a real secret key in production, or fail fast
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY")
    if not SECRET_KEY:
        raise RuntimeError("FLASK_SECRET_KEY environment variable must be set in production!")

    DEBUG = False
    SQLALCHEMY_ECHO = False
