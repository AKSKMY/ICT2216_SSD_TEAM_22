import random
import re

import requests
from dotenv import load_dotenv

from app import has_permission, get_db, is_password_pwned, secret, log_action, mail, Message, User

load_dotenv()  # loads .env file automatically
import pymysql
from datetime import datetime, date, timedelta
import bcrypt
import secrets
from flask import (
    Flask, send_from_directory, render_template,
    request, redirect, url_for, flash, session, current_app, abort, Blueprint
)
from pathlib import Path

#from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import (
    LoginManager, UserMixin, login_user,
    logout_user, login_required, current_user
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

limiter = Limiter(
    get_remote_address,
    app=current_app,
    default_limits=["200 per day", "50 per hour"]  # default for all routes
)

@auth_bp.route("/")
def serve_index():
    return render_template("index.html")

@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def register():
    if current_user.is_authenticated:
        return redirect(url_for("auth.dashboard"))

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
        
        try:
            date_obj = datetime.strptime(date_of_birth_str, "%Y-%m-%d").date()
            if date_obj > date.today():
                flash("Date of birth cannot be in the future.", "error")
                return render_template("register.html")
            
            today = date.today()
            age = today.year - date_obj.year - ((today.month, today.day) < (date_obj.month, date_obj.day))

        except ValueError:
            flash("Invalid date format. Use YYYY-MM-DD.", "error")
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
                    (user_id, first_name, last_name, gender, date_of_birth_str, age)
                )

                conn.commit()
                flash("Registration successful. Please log in.", "success")
                return redirect(url_for("auth.login"))
        except Exception as e:
            conn.rollback()
            flash("Error registering user.", "error")
            print("Registration error:", e)
        finally:
            conn.close()

    return render_template("register.html")

@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("auth.dashboard"))

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
            return redirect(url_for("auth.verify_otp"))
        else:
            log_action(row["user_Id"], f"Login attempt from IP {ip} for username '{username}'")
            flash("Invalid username or password.", "error")

    return render_template("login.html", site_key=site_key)

@auth_bp.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if "pending_user" not in session:
        flash("Session expired. Please log in again.", "error")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        user_otp = request.form.get("otp", "")
        actual_otp = session.get("email_otp")
        expiry = session.get("otp_expiry", 0)

        if datetime.utcnow().timestamp() > expiry:
            flash("OTP has expired. Please log in again.", "error")
            session.clear()
            return redirect(url_for("auth.login"))

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
                session_lifetime_seconds = current_app.permanent_session_lifetime.total_seconds()
                expiry_timestamp = datetime.utcnow().timestamp() + session_lifetime_seconds

                # Delete previous session tokens for this user
                cur.execute("""
                    DELETE FROM critical.user_sessions WHERE user_id = %s
                """, (user_data["user_Id"],))

                # Insert the new session token
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
            return redirect(url_for("auth.dashboard"))
        else:
            flash("Incorrect OTP. Please try again.", "error")

    return render_template("verify_otp.html")

@limiter.limit("3 per 10 minutes")
@auth_bp.route("/resend-otp", methods=["POST"])
def resend_otp():
    if "pending_user" not in session:
        flash("Session expired. Please log in again.", "error")
        return redirect(url_for("auth.login"))

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

    return redirect(url_for("auth.verify_otp"))


@auth_bp.route("/dashboard")
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


# logout
@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))


