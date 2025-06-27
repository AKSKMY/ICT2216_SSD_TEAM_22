import os
import re
from dotenv import load_dotenv

from function import is_password_pwned, create_encrypted_aes_key, log_action, has_permission

load_dotenv()  # loads .env file automatically
import pymysql
from datetime import datetime, date, timedelta
import hashlib
import random
import requests
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail, Message
from flask_wtf import CSRFProtect
import bcrypt
import secrets
from flask import (
    Flask, send_from_directory, render_template,
    request, redirect, url_for, flash, session, current_app, abort
)
from pathlib import Path
from werkzeug.middleware.proxy_fix import ProxyFix

#from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import (
    LoginManager, UserMixin, login_user,
    logout_user, login_required, current_user
)
from config import DevelopmentConfig, ProductionConfig, TestingConfig, secret
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64

# ───────────────────────────────────────────────────────
# FLASK APP CONFIGURATION
# ───────────────────────────────────────────────────────
project_root = os.path.dirname(os.path.abspath(__file__))
html_folder = os.path.join(project_root, "html")
static_folder = os.path.join(project_root, "static")

app = Flask(
    __name__,
    template_folder=html_folder,
    static_folder=static_folder,
    static_url_path="/static"
)

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# Default Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # default for all routes
)

# Decide which config to load based on FLASK_ENV env variable
env = os.getenv("FLASK_ENV", "development").lower()
if env == "production":
    app.config.from_object(ProductionConfig)
elif env == "development":
    app.config.from_object(DevelopmentConfig)
else:
    app.config.from_object(TestingConfig)

mail = Mail(app)

app.secret_key = app.config.get("SECRET_KEY")

# ───────────────────────────────────────────────────────
# LOGIN MANAGER CONFIGURATION
# ───────────────────────────────────────────────────────
login_manager = LoginManager(app)
login_manager.login_view = "auth.login"

# ───────────────────────────────────────────────────────
# DATABASE CONNECTION (MySQL)
# ───────────────────────────────────────────────────────
def get_db():
    return pymysql.connect(
        host=app.config["DB_HOST"],
        user=app.config["DB_USER"],
        password=app.config["DB_PASSWORD"],
        database=app.config["DB_NAME"],
        port=3306,
        cursorclass=pymysql.cursors.DictCursor
    )

# ───────────────────────────────────────────────────────
# USER MODEL
# ───────────────────────────────────────────────────────
class User(UserMixin):
    def __init__(self, user_Id, username, role):
        self.id = user_Id
        self.username = username
        self.role = role

    def get_id(self):
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("""
            SELECT u.user_Id, u.username, r.role_name AS role
            FROM user u
            JOIN userrole ur ON u.user_Id = ur.user_Id
            JOIN role r ON ur.role_Id = r.role_Id
            WHERE u.user_Id = %s
        """, (user_id,))
        row = cur.fetchone()
    conn.close()
    if row:
        return User(row["user_Id"], row["username"], row["role"])
    return None

# Timeout checks
@app.before_request
def session_timeout_check():
    if current_user.is_authenticated:
        now = datetime.utcnow().timestamp()
        last_active = session.get("last_active", now)
        timeout_seconds = app.permanent_session_lifetime.total_seconds()

        # Check if session has expired due to inactivity
        if now - last_active > timeout_seconds:
            # Remove session token from DB
            token = session.get("session_token")
            if token:
                conn = get_db()
                try:
                    with conn.cursor() as cur:
                        cur.execute("""
                            DELETE FROM critical.user_sessions
                            WHERE session_token = %s AND user_id = %s
                        """, (token, current_user.id))
                    conn.commit()
                finally:
                    conn.close()

            logout_user()
            session.clear()
            flash("Session expired due to inactivity. Please log in again.", "warning")
            return redirect(url_for("auth.login"))

        # Session is still valid, update last_active in session
        session["last_active"] = now

        # Update the database's last_active field
        token = session.get("session_token")
        if token:
            conn = get_db()
            try:
                with conn.cursor() as cur:
                    cur.execute("""
                        UPDATE critical.user_sessions
                        SET last_active = NOW()
                        WHERE session_token = %s AND user_id = %s
                    """, (token, current_user.id))
                conn.commit()
            finally:
                conn.close()

# Session Token validation
@app.before_request
def check_valid_session_token():
    if request.endpoint in {"verify_otp", "login", "static"}:
        return
    
    if current_user.is_authenticated:
        token = session.get("session_token")
        if not token:
            logout_user()
            session.clear()
            flash("Session expired. Please log in again.", "warning")
            return redirect(url_for("auth.login"))

        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT 1 FROM critical.user_sessions
                WHERE session_token = %s AND user_id = %s
            """, (token, current_user.id))
            result = cur.fetchone()

        conn.close()
        if not result:
            logout_user()
            session.clear()
            flash("Session revoked or expired. Please log in again.", "warning")
            return redirect(url_for("auth.login"))

# ───────────────────────────────────────────────────────
# GLOBAL TEMPLATE CONTEXT
# Makes `current_user` available in all templates
# ───────────────────────────────────────────────────────
@app.context_processor
def inject_user():
    return dict(current_user=current_user)

# ───────────────────────────────────────────────────────
# TESTING ROUTES
# ───────────────────────────────────────────────────────
@app.route("/test-login-doctor")
def test_login_doctor():
    if not current_app.config.get("TESTING", False):
        abort(404)

    # Get doctor user "bob"
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("""
            SELECT u.user_Id, u.username, r.role_name AS role, u.email
            FROM user u
            JOIN userrole ur ON u.user_Id = ur.user_Id
            JOIN role r ON ur.role_Id = r.role_Id
            WHERE u.username = 'bob' AND r.role_name = 'Doctor'
            LIMIT 1
        """)
        user_row = cur.fetchone()
    conn.close()

    if not user_row:
        return "No test doctor user found", 500

    # Generate a secure session token
    token = secrets.token_urlsafe(64)

    # Set session values
    session["session_token"] = token
    session["last_active"] = datetime.utcnow().timestamp()
    session.permanent = True

    user = User(
        user_Id=user_row["user_Id"],
        username=user_row["username"],
        role=user_row["role"]
    )

    login_user(user)

    # Save session to DB
    conn = get_db()
    with conn.cursor() as cur:
        session_lifetime_seconds = current_app.permanent_session_lifetime.total_seconds()
        expiry_timestamp = datetime.utcnow().timestamp() + session_lifetime_seconds

        cur.execute("""
            INSERT INTO critical.user_sessions (session_token, user_id, ip_address, created_at, last_active, expires_at)
            VALUES (%s, %s, %s, NOW(), NOW(), FROM_UNIXTIME(%s))
        """, (
            token,
            user_row["user_Id"],
            request.remote_addr,
            expiry_timestamp
        ))
        conn.commit()
    conn.close()

    return redirect(url_for("auth.dashboard"))



# ───────────────────────────────────────────────────────
# ROUTES
# ───────────────────────────────────────────────────────
@app.route("/test-db")
def test_db():
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            result = cur.fetchone()
        conn.close()
        return f"Connected! Result: {result}"
    except Exception as e:
        return "An internal error has occurred!"

@app.route("/")
def serve_index():
    return render_template("index.html")


