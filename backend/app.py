import os
import re
from dotenv import load_dotenv
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
from config import DevelopmentConfig, ProductionConfig, TestingConfig
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

def secret(name: str, *, default: str = "") -> str:
    """
    Return the secret value for *name*.

    1. If an env-var called  <NAME>_FILE  exists, read that file
       and return its (trimmed) contents.
    2. Otherwise fall back to the plain env-var  <NAME>.
    3. If neither is present return *default*.
    """
    f = os.getenv(f"{name}_FILE")
    if f and Path(f).is_file():
        return Path(f).read_text(encoding="utf-8").strip()
    return os.getenv(name, default)

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
login_manager.login_view = "login"

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
            return redirect(url_for("login"))

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
            return redirect(url_for("login"))

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
            return redirect(url_for("login"))

# ───────────────────────────────────────────────────────
# GLOBAL TEMPLATE CONTEXT
# Makes `current_user` available in all templates
# ───────────────────────────────────────────────────────
@app.context_processor
def inject_user():
    return dict(current_user=current_user)

# ───────────────────────────────────────────────────────
# Functions
# ───────────────────────────────────────────────────────
def has_permission(user_id, permission_name):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("""
            SELECT 1
            FROM user u
            JOIN userrole ur ON u.user_Id = ur.user_Id
            JOIN rolepermission rp ON ur.role_Id = rp.role_Id
            JOIN permission p ON rp.permission_Id = p.permission_Id
            WHERE u.user_Id = %s AND p.permission_name = %s
            LIMIT 1
        """, (user_id, permission_name))
        return cur.fetchone() is not None
    
def log_action(user_id, description):
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO rbac.audit_log (user_Id, description)
                VALUES (%s, %s)
            """, (user_id, description))
        conn.commit()
    except Exception as e:
        print("Audit log error:", e)
    finally:
        conn.close()

def is_password_pwned(password):
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    if response.status_code != 200:
        # Assume safe if the API fails
        return False  
    hashes = (line.split(":") for line in response.text.splitlines())
    return any(s == suffix for s, _ in hashes)

# Use master key to decrypt encrypted KEK to obtain KEK so it can be used
def decrypt_with_master_key(encoded_encrypted: str, master_key: bytes) -> bytes:
    aesgcm = AESGCM(master_key)
    encrypted = base64.b64decode(encoded_encrypted)

    nonce = encrypted[:12]
    ciphertext = encrypted[12:]

    return aesgcm.decrypt(nonce, ciphertext, None)

# Get encrypted kek from critical database according to kek_id
def get_encrypted_kek_from_db(kek_id):
    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT kek_value FROM critical.kek WHERE kek_id = %s", (kek_id,))
        result = cursor.fetchone()
        if result is None:
            raise ValueError(f"KEK with id {kek_id} not found in the database.")
        return result['kek_value']  # the base64 string
    finally:
        cursor.close()

# Use kek to encrypt the plaintext in order to store it 
def encrypt_with_kek(plaintext: bytes, kek_id: int):
    try:
        master_key = base64.b64decode(secret('KEK_MASTER_KEY'))
        encrypted_kek = get_encrypted_kek_from_db(kek_id)
        dec_kek = decrypt_with_master_key(encrypted_kek, master_key)
        if not dec_kek:
            print("❌ Failed to decrypt KEK.")
            return None
        aesgcm = AESGCM(dec_kek)
        nonce = os.urandom(12)
        encrypted = aesgcm.encrypt(nonce, plaintext, None)
        return base64.b64encode(nonce + encrypted).decode("utf-8")
    except Exception as e:
        return(f"❌ Error! Check with admin")
        

# Create AES key that is encrypted with appropriate KEK
def create_encrypted_aes_key(kek_id):
    aes_key = os.urandom(32)
    return encrypt_with_kek(aes_key, kek_id)

# Create RSA key that is encrypted with appropriate KEK    
def create_encrypted_RSA_key():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    return encrypt_with_kek(private_bytes, 2)

def get_encrypted_key(user_id, user_role):
    conn = get_db()
    cursor = conn.cursor()
    try:
        if (user_role == "Doctor"):
            cursor.execute("SELECT private_enc_key FROM critical.doctor_priv_key WHERE doctor_id = %s", (user_id,))
            result = cursor.fetchone()
            if result is None:
                raise ValueError(f"KEK with id {user_id} not found in the database.")
            return result['private_enc_key']  # the base64 string
        elif (user_role == "Patient"):
            cursor.execute("SELECT patient_AES_key FROM critical.patient_encryption_key WHERE patient_id = %s", (user_id,))
            result = cursor.fetchone()
            if result is None:
                raise ValueError(f"KEK with id {user_id} not found in the database.")
            return result['patient_AES_key']  # the base64 string
        elif (user_role == "Admin"):
            cursor.execute("SELECT admin_AES_key FROM critical.admin_encryption_key WHERE id = %s", (user_id,))
            result = cursor.fetchone()
            if result is None:
                raise ValueError(f"KEK with id {user_id} not found in the database.")
            return result['admin_AES_key']  # the base64 string
        else:
            print("Your role does not have a key.")
    finally:
        cursor.close()

def decrypt_with_aes(enc_key, dec_kek):
    encrypted = base64.b64decode(enc_key)
    nonce = encrypted[:12]
    ciphertext = encrypted[12:]
    aesgcm = AESGCM(dec_kek)
    return aesgcm.decrypt(nonce, ciphertext, None)
        
def encrypt_with_aes_key(aes_key, plaintext):
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode("utf-8")

def encrypt_medical_records(patient_id, plaintext):
    try:
        master_key = base64.b64decode(secret('KEK_MASTER_KEY'))
        encrypted_kek = get_encrypted_kek_from_db(1)
        dec_kek = decrypt_with_master_key(encrypted_kek, master_key)
        enc_key = get_encrypted_key(patient_id, "Patient")
        patient_key = decrypt_with_aes(enc_key, dec_kek)
        return encrypt_with_aes_key(patient_key, plaintext)
    except Exception as e:
        return(f"❌ Error! Check with admin")
        
def decrypt_AES_cipher(ciphertext, user_id, user_role):
    try:
        master_key = base64.b64decode(secret('KEK_MASTER_KEY'))
        if user_role == "Patient":
            user_role_number = 1
        elif user_role == "Admin":
            user_role_number = 3
        encrypted_kek = get_encrypted_kek_from_db(user_role_number)
        dec_kek = decrypt_with_master_key(encrypted_kek, master_key)
        enc_key = get_encrypted_key(user_id, user_role)
        user_key = decrypt_with_aes(enc_key, dec_kek)
        return decrypt_with_aes(ciphertext, user_key).decode("utf-8")
    except Exception as e:
        return(f"❌ Error! Check with admin")

# Function to view table for debugging    
def view_table_data(table_name):
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(f"SELECT * FROM {table_name}")
        rows = cur.fetchall()
        print(f"\n📋 Data in `{table_name}`:")
        for row in rows:
            print(row)
    except Exception as e:
        print(f"❌ Error reading table `{table_name}`:", e)
    finally:
        cur.close()

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

    return redirect("/dashboard")



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
        return f"Failed: {e}"

@app.route("/")
def serve_index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        # User Table
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        # Input Validation
        if len(password) < 8:                                   
            flash("Password must be at least 8 characters.",    
              "error")                                       
            return render_template("register.html") 

        # Patient Table
        first_name = request.form.get("first_name", "")
        last_name = request.form.get("last_name", "")
        gender = request.form.get("gender", "")
        date_of_birth_str = request.form.get("date_of_birth")
        age = request.form.get('age', '').strip()

        # Regex
        username_regex = r"^[a-zA-Z0-9_]{3,20}$"
        email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

        # Validation
        if not re.match(username_regex, username):
            flash("Username must be 3–20 characters long and alphanumeric (underscores allowed).", "error")
            return render_template("register.html")

        if not re.match(email_regex, email):
            flash("Please enter a valid email address.", "error")
            return render_template("register.html")

        # To check if password is breached
        if is_password_pwned(password):
            flash("This password has appeared in a data breach. Please choose another.", "error")
            return render_template("register.html")

        if not first_name or not last_name:
            flash("First name and last name are required.", "error")
            return render_template("register.html")

        if gender not in {"Male", "Female", "Other"}:
            flash("Please select a valid gender.", "error")
            return render_template("register.html")

        if not age.isdigit() or int(age) < 0:
            flash("Age must be a positive number.", "error")
            return render_template("register.html")

        # Validate date format
        try:
            date_obj = datetime.strptime(date_of_birth_str, "%Y-%m-%d").date()
            if date_obj > date.today():
                flash("Date of birth cannot be in the future.", "error")
                return render_template("register.html")
        except ValueError:
            flash("Invalid date format. Use YYYY-MM-DD.", "error")
            return render_template("register.html")

        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM user WHERE username = %s", (username,))
                if cur.fetchone():
                    flash("Username already exists.", "error")
                    return render_template("register.html")

                cur.execute("SELECT role_Id FROM role WHERE role_name = %s", ("Patient",))
                roleresult = cur.fetchone()
                role_id = roleresult['role_Id']
                salt = bcrypt.gensalt()
                hashed_pw = bcrypt.hashpw(password.encode('utf-8'), salt)

                cur.execute(
                    "INSERT INTO user (username, email, password, salt) VALUES (%s, %s, %s, %s)",
                    (username, email, hashed_pw, salt)
                )

                user_id = cur.lastrowid

                cur.execute("INSERT INTO userrole (user_Id, role_Id) VALUES (%s, %s)", (user_id, role_id))
                cur.execute(
                    """
                    INSERT INTO patient (user_Id, first_name, last_name, gender, data_of_birth, age)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (user_id, first_name, last_name, gender, date_of_birth_str, int(age))
                )

                encrypted_aes_key = create_encrypted_aes_key(1)
                cur.execute("INSERT INTO critical.patient_encryption_key VALUES (%s, %s, %s)", (user_id, encrypted_aes_key, 1))
                conn.commit()
                flash("Registration successful. Please log in.", "success")
                return redirect(url_for("login"))
        except Exception as e:
            conn.rollback()
            flash("Error registering user.", "error")
            print("Registration error:", e)
        finally:
            conn.close()

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    site_key = secret("RECAPTCHA_SITE_KEY")
    secret_key = secret("RECAPTCHA_SECRET_KEY")
    
    if request.method == "POST":
        # reCAPTCHA verification
        recaptcha_response = request.form.get("g-recaptcha-response")
        verify_url = "https://www.google.com/recaptcha/api/siteverify"
        payload = {
            'secret': secret_key,
            'response': recaptcha_response,
            'remoteip': request.remote_addr
        }
        recaptcha_result = requests.post(verify_url, data=payload).json()
        if not recaptcha_result.get("success"):
            flash("reCAPTCHA failed. Please try again.", "error")
            return render_template("login.html", site_key=site_key)

        ip = request.remote_addr
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        # Input Validtion
        username_regex = r"^[a-zA-Z0-9_.]{3,30}$"
        
        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("login.html")

        if not re.match(username_regex, username):
            flash("Invalid username format.", "error")
            return render_template("login.html")

        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT u.user_Id, u.username, u.email, u.password, u.salt, r.role_name AS role
                FROM user u
                JOIN userrole ur ON u.user_Id = ur.user_Id
                JOIN role r ON ur.role_Id = r.role_Id
                WHERE u.username = %s
            """, (username,))
            row = cur.fetchone()
        conn.close()
        
        if row and bcrypt.checkpw(password.encode('utf-8'), row["password"].encode('utf-8')):
            # Generate OTP
            otp = str(random.randint(100000, 999999))
            session["pending_user"] = {
                "user_Id": row["user_Id"],
                "username": row["username"],
                "role": row["role"],
                "email": row["email"]
            }
            session["email_otp"] = otp
            session["otp_expiry"] = datetime.utcnow().timestamp() + 300  # 5 minutes

            # Send email
            try:
                msg = Message("Your MediVault OTP Code", recipients=[row["email"]])
                msg.body = f"Your OTP is: {otp}. It expires in 5 minutes."
                mail.send(msg)
                flash("An OTP has been sent to your email.", "success")
            except Exception as e:
                print("Email error:", e)
                flash("Failed to send OTP. Please try again.", "error")
                return render_template("login.html")
            return redirect(url_for("verify_otp"))
        else:
            log_action(None, f"Login attempt from IP {ip} for username '{username}'")
            flash("Invalid username or password.", "error")

    return render_template("login.html", site_key=site_key)

@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if "pending_user" not in session:
        flash("Session expired. Please log in again.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        user_otp = request.form.get("otp", "")
        actual_otp = session.get("email_otp")
        expiry = session.get("otp_expiry", 0)

        if datetime.utcnow().timestamp() > expiry:
            flash("OTP has expired. Please log in again.", "error")
            session.clear()
            return redirect(url_for("login"))

        if user_otp == actual_otp:
            token = secrets.token_urlsafe(64)
            session["session_token"] = token
            
            user_data = session["pending_user"]
            user = User(
                user_Id=user_data["user_Id"],
                username=user_data["username"],
                role=user_data["role"]
            )
            
            session.permanent = True
            session["last_active"] = datetime.utcnow().timestamp()
            conn = get_db()
            
            with conn.cursor() as cur:
                session_lifetime_seconds = app.permanent_session_lifetime.total_seconds()
                expiry_timestamp = datetime.utcnow().timestamp() + session_lifetime_seconds

                cur.execute("""
                    INSERT INTO critical.user_sessions (session_token, user_id, ip_address, created_at, last_active, expires_at)
                    VALUES (%s, %s, %s, NOW(), NOW(), FROM_UNIXTIME(%s))
                """, (
                    token,
                    user_data["user_Id"],
                    request.remote_addr,
                    expiry_timestamp
                ))
                conn.commit()
            conn.close()
            
            login_user(user)

            session.pop("pending_user", None)
            session.pop("email_otp", None)
            session.pop("otp_expiry", None)

            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Incorrect OTP. Please try again.", "error")

    return render_template("verify_otp.html")

@limiter.limit("3 per 10 minutes")
@app.route("/resend-otp", methods=["POST"])
def resend_otp():
    if "pending_user" not in session:
        flash("Session expired. Please log in again.", "error")
        return redirect(url_for("login"))

    # Generate new OTP
    otp = str(random.randint(100000, 999999))
    session["email_otp"] = otp
    session["otp_expiry"] = datetime.utcnow().timestamp() + 300  # 5 minutes

    # Send email
    user_email = session.get("email") or session["pending_user"].get("email")  # In case you store email later
    if not user_email:
        # Refetch from DB if not stored
        user_id = session["pending_user"]["user_Id"]
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("SELECT email FROM user WHERE user_Id = %s", (user_id,))
            result = cur.fetchone()
            if result:
                user_email = result["email"]
        conn.close()

    try:
        msg = Message("Your MediVault OTP Code", recipients=[user_email])
        msg.body = f"Your new OTP is: {otp}. It expires in 5 minutes."
        mail.send(msg)
        flash("A new OTP has been sent to your email.", "success")
    except Exception as e:
        print("Resend OTP error:", e)
        flash("Failed to resend OTP. Please try again.", "error")

    return redirect(url_for("verify_otp"))


@app.route("/dashboard")
@login_required
def dashboard():
    admin_data = None
    doctor_data = None
    nurse_data = None

    conn = get_db()
    with conn.cursor(pymysql.cursors.DictCursor) as cur:
        if current_user.role == "Admin":
            cur.execute("SELECT COUNT(*) AS total FROM user")
            total_users = cur.fetchone()['total']

            cur.execute("""
                SELECT r.role_name, COUNT(*) AS count
                FROM user u
                JOIN userrole ur ON u.user_Id = ur.user_Id
                JOIN role r ON ur.role_Id = r.role_Id
                GROUP BY r.role_name
            """)
            role_counts = {row['role_name']: row['count'] for row in cur.fetchall()}

            admin_data = {
                "total_users": total_users,
                "total_doctors": role_counts.get("Doctor", 0),
                "total_nurses": role_counts.get("Nurse", 0),
                "total_patients": role_counts.get("Patient", 0),
            }

        elif current_user.role == "Doctor":
            # Count patients seen by this doctor
            cur.execute("""
                SELECT COUNT(DISTINCT p.user_Id) AS total_patients
                FROM rbac.patient p
                JOIN rbac.medical_record mr ON p.user_Id = mr.patient_id
                WHERE mr.doctor_id = %s
            """, (current_user.id,))
            total_patients = cur.fetchone()['total_patients']

            cur.execute("""
                SELECT mr.record_id, mr.diagnosis, mr.date,
                       p.first_name AS patient_first_name, p.last_name AS patient_last_name
                FROM rbac.medical_record mr
                JOIN rbac.patient p ON mr.patient_id = p.user_Id
                WHERE mr.doctor_id = %s
                ORDER BY mr.date DESC
                LIMIT 3
            """, (current_user.id,))
            recent_records = cur.fetchall()

            doctor_data = {
                "total_patients": total_patients,
                "recent_records": recent_records
            }

        elif current_user.role == "Nurse":
            # Count all unique patients in the system (nurses see all)
            cur.execute("SELECT COUNT(DISTINCT user_Id) AS total_patients FROM rbac.patient")
            total_patients = cur.fetchone()['total_patients']

            cur.execute("""
                SELECT mr.record_id, mr.diagnosis, mr.date,
                       p.first_name AS patient_first_name, p.last_name AS patient_last_name
                FROM rbac.medical_record mr
                JOIN rbac.patient p ON mr.patient_id = p.user_Id
                ORDER BY mr.date DESC
                LIMIT 3
            """)
            recent_records = cur.fetchall()

            nurse_data = {
                "total_patients": total_patients,
                "recent_records": recent_records
            }

    conn.close()

    return render_template("dashboard.html",admin_data=admin_data, doctor_data=doctor_data, nurse_data=nurse_data)


@app.route("/admin/viewUsers")
@login_required
def view_users():
    if current_user.role != 'Admin':
        flash("Access denied.", "error")
        return redirect(url_for("dashboard"))

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("""
            SELECT u.user_Id, u.username, u.email, r.role_name AS role
            FROM user u
            JOIN userrole ur ON u.user_Id = ur.user_Id
            JOIN role r ON ur.role_Id = r.role_Id
            WHERE r.role_name IN ('Patient', 'Doctor', 'Nurse')
            ORDER BY r.role_name, u.username
        """)
        users = cur.fetchall()

    return render_template("admin_viewUsers.html", users=users)

@app.route("/admin/editUser/<int:user_id>", methods=["GET", "POST"])
@login_required
def edit_user(user_id):
    if current_user.role != 'Admin' or not has_permission(current_user.id, "Manage Users"):
        flash("Access denied.", "error")
        return redirect(url_for("dashboard"))

    conn = get_db()
    with conn.cursor() as cur:
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip()

            # Validate fields
            if not username or not email:
                flash("Username and email are required.", "error")
                return render_template("admin_editUsers.html", user=user, user_id=user_id)

            # Check email format with regex
            email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
            if not re.match(email_regex, email):
                flash("Invalid email format.", "error")
                return render_template("admin_editUsers.html", user=user, user_id=user_id)
    
            cur.execute("UPDATE user SET username = %s, email = %s WHERE user_Id = %s",
                        (username, email, user_id))
            conn.commit()
            flash("User updated successfully.", "success")
            return redirect(url_for("view_users"))

        cur.execute("SELECT username, email FROM user WHERE user_Id = %s", (user_id,))
        user = cur.fetchone()
    conn.close()

    if not user:
        flash("User not found.", "error")
        return redirect(url_for("view_users"))

    return render_template("admin_editUsers.html", user=user, user_id=user_id)

@app.route("/admin/deleteUser/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    if current_user.role != 'Admin' or not has_permission(current_user.id, "Manage Users"):
        flash("Access denied.", "error")
        return redirect(url_for("dashboard"))

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM userrole WHERE user_Id = %s", (user_id,))
            cur.execute("DELETE FROM user WHERE user_Id = %s", (user_id,))
        conn.commit()
        flash("User deleted successfully.", "success")
    except Exception as e:
        conn.rollback()
        flash("Failed to delete user.", "error")
        print("Delete error:", e)
    finally:
        conn.close()

    return redirect(url_for("view_users"))

@app.route("/admin/createAccount", methods=["GET", "POST"])
@login_required
def create_account():
    if current_user.role != 'Admin' or not has_permission(current_user.id, "Manage Users"):
        flash("Access denied.", "error")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        # Basic fields
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        role_name = request.form.get("role", "").strip()

        # Extra fields for staff
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        age = request.form.get("age", "").strip()
        gender = request.form.get("gender", "").strip()

        # Regex
        username_regex = r"^[a-zA-Z0-9_]{3,20}$"
        email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

        # Basic validation
        if not username or not email or not password or not role_name:
            flash("All fields are required.", "error")
            return render_template("admin_createAccount.html")
        
        if not re.match(username_regex, username):
            flash("Username must be 3–20 characters long and alphanumeric (underscores allowed).", "error")
            return render_template("admin_createAccount.html")
        
        if not re.match(email_regex, email):
            flash("Please enter a valid email address.", "error")
            return render_template("admin_createAccount.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("admin_createAccount.html")

        valid_roles = {"Doctor", "Nurse"}
        if role_name not in valid_roles:
            flash("Invalid role selected.", "error")
            return render_template("admin_createAccount.html")

        if not first_name or not last_name or not age or not gender:
            flash("All staff fields are required for Doctor/Nurse.", "error")
            return render_template("admin_createAccount.html")

        if not age.isdigit() or int(age) < 0:
            flash("Age must be a valid positive number.", "error")
            return render_template("admin_createAccount.html")

        if gender not in {"Male", "Female", "Other"}:
            flash("Please select a valid gender.", "error")
            return render_template("admin_createAccount.html")

        conn = get_db()
        try:
            with conn.cursor() as cur:
                # Check username uniqueness
                cur.execute("SELECT 1 FROM user WHERE username = %s", (username,))
                if cur.fetchone():
                    flash("Username already exists.", "error")
                    return render_template("admin_createAccount.html")

                # Get role ID
                cur.execute("SELECT role_Id FROM role WHERE role_name = %s", (role_name,))
                role_row = cur.fetchone()
                if not role_row:
                    flash("Role lookup failed.", "error")
                    return render_template("admin_createAccount.html")
                role_id = role_row["role_Id"]

                def bcrypt_hash(password: str, rounds: int = 12) -> tuple[bytes, bytes]:

                    salt = bcrypt.gensalt(rounds=rounds)
                    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
                    return hashed, salt






                # Insert into user table
                #hashed_pw = generate_password_hash(password) (old method using werkzeug)
                hashed_pw, salt = bcrypt_hash(password)
                cur.execute("INSERT INTO user (username, email, password,salt) VALUES (%s, %s, %s,%s)",
                            (username, email, hashed_pw,salt))
                user_id = cur.lastrowid

                # Insert into userrole table
                cur.execute("INSERT INTO userrole (user_Id, role_Id) VALUES (%s, %s)", (user_id, role_id))

                # Insert into staff table
                if role_name == "Doctor":
                    cur.execute("""INSERT INTO rbac.doctor (user_Id, first_name, last_name, age, gender)
                                   VALUES (%s, %s, %s, %s, %s)""",
                                (user_id, first_name, last_name, int(age), gender))
                elif role_name == "Nurse":
                    cur.execute("""INSERT INTO rbac.nurse (user_Id, first_name, last_name, age, gender)
                                   VALUES (%s, %s, %s, %s, %s)""",
                                (user_id, first_name, last_name, int(age), gender))

                # Generate RSA key if Doctor
                if role_name == "Doctor":
                    encrypted_rsa_key = create_encrypted_RSA_key()

                conn.commit()
                flash(f"{role_name} account created successfully!", "success")
        except Exception as e:
            conn.rollback()
            flash("Error creating account.", "error")
            print("Create account error:", e)
        finally:
            conn.close()

    return render_template("admin_createAccount.html")


# Admin - View Audit Logs
@app.route("/admin/viewLogs")
@login_required
def view_logs():
    if current_user.role != 'Admin':
        flash("Access denied.", "error")
        return redirect(url_for("dashboard"))

    conn = get_db()
    with conn.cursor(pymysql.cursors.DictCursor) as cur:
        cur.execute("""
            SELECT al.log_id, al.user_Id AS user_id, u.username, al.description AS action, al.timestamp
            FROM rbac.audit_log al
            JOIN rbac.user u ON al.user_Id = u.user_Id
            ORDER BY al.timestamp DESC
        """)
        logs = cur.fetchall()

    return render_template("admin_viewLogs.html", logs=logs)

# Nurse - View patients
@app.route("/nurse/viewPatients", methods=["GET", "POST"])
@login_required
def nurse_view_patients():
    if current_user.role != 'Nurse' or not has_permission(current_user.id, "View Medical Records"):
        flash("Access denied.", "error")
        return redirect(url_for("dashboard"))

    search_query = request.args.get("search", "").strip()
    if search_query and not re.match(r"^[a-zA-Z\s\-']{1,50}$", search_query):
        flash("Invalid characters in search. Only letters and basic punctuation are allowed.", "error")
        return redirect(url_for("nurse_view_patients"))

    conn = get_db()
    with conn.cursor() as cur:
        if search_query:
            like_pattern = f"%{search_query}%"
            cur.execute("""
                SELECT DISTINCT p.user_Id, p.first_name, p.last_name, p.age, p.gender, p.data_of_birth
                FROM rbac.patient p
                WHERE p.first_name LIKE %s OR p.last_name LIKE %s
            """, (like_pattern, like_pattern))
        else:
            cur.execute("""
                SELECT DISTINCT p.user_Id, p.first_name, p.last_name, p.age, p.gender, p.data_of_birth
                FROM rbac.patient p
            """)
        users = cur.fetchall()

    return render_template("viewPatients.html", users=users, search_query=search_query)

# Nurse - View patients
@app.route('/nurse/patientRecords/<int:patient_id>')
@login_required
def nurse_view_patient_records(patient_id):
    if current_user.role != 'Nurse' or not has_permission(current_user.id, "View Medical Records"):
        flash("Access denied.", "error")
        return redirect(url_for("dashboard"))

    conn = get_db()
    with conn.cursor(pymysql.cursors.DictCursor) as cur:
        cur.execute("""
            SELECT mr.record_id, mr.diagnosis, mr.date,
                   mr.patient_id,
                   p.first_name AS patient_first_name, p.last_name AS patient_last_name,
                   d.first_name AS doctor_first_name, d.last_name AS doctor_last_name
            FROM rbac.medical_record mr
            JOIN rbac.patient p ON mr.patient_id = p.user_Id
            JOIN rbac.doctor d ON mr.doctor_id = d.user_Id
            WHERE mr.patient_id = %s
            ORDER BY mr.date DESC
        """, (patient_id,))
        records = cur.fetchall()
        for record in records:
            try:
                record["diagnosis"] = decrypt_AES_cipher(record["diagnosis"], record["patient_id"], "Patient")
            except Exception as e:
                record["diagnosis"] = "[Decryption failed]"
                print(f"Decryption error for record {record['record_id']}: {e}")

    return render_template("medicalRecord.html", records=records, patient_id=patient_id)


# Doctor - View patients
@app.route("/doctor/viewPatients", methods=["GET", "POST"])
@login_required
def doctor_view_patients():
    if current_user.role != 'Doctor' or not has_permission(current_user.id, "View Medical Records"):
        flash("Access denied.", "error")
        return redirect(url_for("dashboard"))

    search_query = request.args.get("search", "").strip()
    if search_query and not re.match(r"^[a-zA-Z\s\-']{1,50}$", search_query):
        flash("Invalid characters in search. Only letters and basic punctuation are allowed.", "error")
        return redirect(url_for("doctor_view_patients"))

    conn = get_db()
    with conn.cursor() as cur:
        if search_query:
            like_pattern = f"%{search_query}%"
            cur.execute("""
                SELECT DISTINCT p.user_Id, p.first_name, p.last_name, p.age, p.gender, p.data_of_birth
                FROM rbac.patient p
                WHERE p.first_name LIKE %s OR p.last_name LIKE %s
            """, (like_pattern, like_pattern))
        else:
            cur.execute("""
                SELECT DISTINCT p.user_Id, p.first_name, p.last_name, p.age, p.gender, p.data_of_birth
                FROM rbac.patient p
            """)
        users = cur.fetchall()

    return render_template("viewPatients.html", users=users, search_query=search_query)

# Doctor - View Medical records
@app.route('/doctor/patientRecords/<int:patient_id>')
@login_required
def doctor_view_patient_records(patient_id):
    if current_user.role != 'Doctor' or not has_permission(current_user.id, "View Medical Records"):
        flash("Access denied.", "error")
        return redirect(url_for("dashboard"))

    conn = get_db()
    with conn.cursor(pymysql.cursors.DictCursor) as cur:
        cur.execute("""
            SELECT mr.record_id, mr.diagnosis, mr.date,
                   mr.patient_id,
                   p.first_name AS patient_first_name, p.last_name AS patient_last_name,
                   d.first_name AS doctor_first_name, d.last_name AS doctor_last_name
            FROM rbac.medical_record mr
            JOIN rbac.patient p ON mr.patient_id = p.user_Id
            JOIN rbac.doctor d ON mr.doctor_id = d.user_Id
            WHERE mr.patient_id = %s AND mr.doctor_id = %s
            ORDER BY mr.date DESC
        """, (patient_id, current_user.id))
        records = cur.fetchall()
        for record in records:
            try:
                record["diagnosis"] = decrypt_AES_cipher(record["diagnosis"], patient_id, "Patient")
            except Exception as e:
                record["diagnosis"] = "[Decryption failed]"
                print(f"Decryption error for record {record['record_id']}: {e}")
    return render_template("medicalRecord.html", records=records, patient_id=patient_id)


# Doctor - Add Medical Records
@app.route('/doctor/addRecord/<int:patient_id>', methods=['GET', 'POST'])
@login_required
def add_medical_record(patient_id):
    if current_user.role != 'Doctor' or not has_permission(current_user.id, "Edit Medical Records"):
        flash("Access denied.", "error")
        return redirect(url_for("dashboard"))

    conn = get_db()

    if request.method == 'POST':
        # Strip leading/trailing spaces
        diagnosis = request.form.get('diagnosis', '').strip()
        record_date = request.form.get('date')

        # Basic input presence check
        if not diagnosis or not record_date:
            flash("All fields are required.", "error")
            return render_template('doctor_addRecord.html', patient_id=patient_id)

        # Validate and sanitize date
        try:
            date_obj = datetime.strptime(record_date, "%Y-%m-%d").date()
            if date_obj > date.today():
                flash("Date cannot be in the future.", "error")
                return render_template('doctor_addRecord.html', patient_id=patient_id)
        except ValueError:
            flash("Invalid date format.", "error")
            return render_template('doctor_addRecord.html', patient_id=patient_id)

        with conn.cursor() as cur:
            # Ensure patient exists
            cur.execute("SELECT 1 FROM rbac.patient WHERE user_Id = %s", (patient_id,))
            if not cur.fetchone():
                flash("Patient not found.", "error")
                return redirect(url_for("dashboard"))
            
            # Encrypt the diagnosis with patient's AES key
            diagnosis = encrypt_medical_records(patient_id, diagnosis)

            # Insert medical record
            cur.execute("""
                INSERT INTO rbac.medical_record (patient_id, diagnosis, doctor_id, date)
                VALUES (%s, %s, %s, %s)
            """, (patient_id, diagnosis, current_user.id, date_obj))
            conn.commit()
            log_action(current_user.id, f"Doctor added a medical record for patient ID {patient_id}.")

        flash("Medical record added successfully!", "success")
        return redirect(url_for('doctor_view_patient_records', patient_id=patient_id))

    return render_template('doctor_addRecord.html', patient_id=patient_id)

# Doctor - Edit Medical records
@app.route('/doctor/editRecord/<int:record_id>', methods=['GET', 'POST'])
@login_required
def edit_medical_record(record_id):
    if current_user.role != 'Doctor' or not has_permission(current_user.id, "Edit Medical Records"):
        flash("Access denied.", "error")
        return redirect(url_for("dashboard"))

    conn = get_db()
    with conn.cursor(pymysql.cursors.DictCursor) as cur:
        # Fetch the existing record by ID
        cur.execute("""
            SELECT record_id, diagnosis, date, patient_id
            FROM rbac.medical_record
            WHERE record_id = %s AND doctor_id = %s
        """, (record_id, current_user.id))
        record = cur.fetchone()
        try:
            record["diagnosis"] = decrypt_AES_cipher(record["diagnosis"], record["patient_id"], "Patient")
        except Exception as e:
            record["diagnosis"] = "[Decryption failed]"
            print(f"Decryption error for record {record['record_id']}: {e}")
    if not record:
        flash("Medical record not found or access denied.", "error")
        return redirect(url_for("dashboard"))
    
    if request.method == 'POST':
        diagnosis = request.form.get('diagnosis', '').strip()
        date_str = request.form.get('date', '').strip()

        # Basic required fields check
        if not diagnosis or not date_str:
            flash("All fields are required.", "error")
            return render_template('doctor_editRecord.html', record=record)

        # Validate date format
        try:
            record_date = datetime.strptime(date_str, '%Y-%m-%d').date()
            today = datetime.today().date()
            if record_date > today:
                flash("Date cannot be in the future.", "error")
                return render_template('doctor_editRecord.html', record=record)
        except ValueError:
            flash("Invalid date format.", "error")
            return redirect(request.url)
        
        diagnosis = encrypt_medical_records(record["patient_id"], diagnosis)

        with conn.cursor() as cur:
            cur.execute("""
                UPDATE rbac.medical_record
                SET diagnosis = %s, date = %s
                WHERE record_id = %s AND doctor_id = %s
            """, (diagnosis, date_str, record_id, current_user.id))
            conn.commit()
            log_action(current_user.id, f"Doctor edited medical record ID {record_id}.")

        flash("Medical record updated successfully!", "success")
        return redirect(url_for('doctor_view_patient_records', patient_id=record['patient_id']))

    return render_template('doctor_editRecord.html', record=record)

# Doctor - Add Patients
@app.route('/doctor/addPatient', methods=['GET', 'POST'])
@login_required
def add_patient():

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("""
            SELECT u.user_Id, u.username
            FROM rbac.user u
            JOIN rbac.userrole ur ON u.user_Id = ur.user_Id
            WHERE ur.role_Id = 1
            AND u.user_Id NOT IN (SELECT user_Id FROM rbac.patient)
        """)
        patient_users = cur.fetchall()

    if request.method == 'POST':
        user_id = request.form.get('user_id', '').strip()
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        age = request.form.get('age', '').strip()
        gender = request.form.get('gender', '').strip()
        dob = request.form.get('date_of_birth', '').strip()

        # Validate required fields
        if not user_id or not first_name or not last_name or not age or not dob:
            flash("User, First Name, Last Name, Age, and Date of Birth are required.", "error")
            return render_template("doctor_addPatients.html", patient_users=patient_users)

        # Validate user_id is integer and exists in patient_users
        try:
            user_id_int = int(user_id)
        except ValueError:
            flash("Invalid user selection.", "error")
            return render_template("doctor_addPatients.html", patient_users=patient_users)

        # Check if user_id is in patient_users list (to prevent tampering)
        if not any(u['user_Id'] == user_id_int for u in patient_users):
            flash("Selected user is invalid or already a patient.", "error")
            return render_template("doctor_addPatients.html", patient_users=patient_users)

        # Validate gender
        valid_genders = {'Male', 'Female', 'Other'}
        if gender not in valid_genders:
            flash("Invalid gender selected.", "error")
            return render_template("doctor_addPatients.html", patient_users=patient_users)
        gender = gender if gender else None

        # Validate date_of_birth
        if dob:
            try:
                dob_date = datetime.strptime(dob, '%Y-%m-%d').date()
                today = datetime.today().date()
                if dob_date > today:
                    flash("Date of birth cannot be in the future.", "error")
                    return render_template("doctor_addPatients.html", patient_users=patient_users)
            except ValueError:
                flash("Invalid date of birth format.", "error")
                return render_template("doctor_addPatients.html", patient_users=patient_users)
        else:
            dob_date = None

        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO rbac.patient (user_Id, first_name, last_name, age, gender, data_of_birth)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (user_id_int, first_name, last_name, age, gender, dob_date))
            conn.commit()

        flash("Patient added successfully!", "success")
        return redirect(url_for('view_patients'))

    return render_template("doctor_addPatients.html", patient_users=patient_users)

# Patient - View Medical Records
@app.route('/user/patientRecords')
@login_required
def view_medicalRecords():
    if current_user.role != 'Patient' or not has_permission(current_user.id, "View Medical Records"):
        flash("Access denied.", "error")
        return redirect(url_for("dashboard"))

    conn = get_db()
    with conn.cursor(pymysql.cursors.DictCursor) as cur:
        # Validate patient exists
        cur.execute("SELECT user_Id FROM rbac.patient WHERE user_Id = %s", (current_user.id,))
        result = cur.fetchone()
        if not result:
            flash("Patient profile not found.", "error")
            return redirect(url_for("dashboard"))

        patient_id = result["user_Id"]

        # Fetch medical records for the patient
        cur.execute("""
            SELECT mr.record_id, mr.diagnosis, mr.date,
                   d.first_name AS doctor_first_name, d.last_name AS doctor_last_name,
                   p.first_name AS patient_first_name, p.last_name AS patient_last_name
            FROM rbac.medical_record mr
            JOIN rbac.doctor d ON mr.doctor_id = d.user_Id
            JOIN rbac.patient p ON mr.patient_id = p.user_Id
            WHERE mr.patient_id = %s
            ORDER BY mr.date DESC
        """, (patient_id,))
        records = cur.fetchall()
        for record in records:
            try:
                record["diagnosis"] = decrypt_AES_cipher(record["diagnosis"], current_user.id, "Patient")
            except Exception as e:
                record["diagnosis"] = "[Decryption failed]"
                print(f"Decryption error for record {record['record_id']}: {e}")
    return render_template('medicalRecord.html', records=records)

# logout
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug_mode = app.config.get("DEBUG", False)
    app.run(debug=debug_mode, host="0.0.0.0", port=port)
