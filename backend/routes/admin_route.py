import re
from dotenv import load_dotenv

from function import get_db, has_permission, decrypt_admin_log, create_encrypted_RSA_key
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


adm_bp = Blueprint('admin', __name__, url_prefix='/admin')


@adm_bp.route("/viewUsers")
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


@adm_bp.route("/editUser/<int:user_id>", methods=["GET", "POST"])
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
                return redirect(url_for("edit_user", user_id=user_id))

            # Check email format with regex
            email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
            if not re.match(email_regex, email):
                flash("Invalid email format.", "error")
                return redirect(url_for("edit_user", user_id=user_id))

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


@adm_bp.route("/deleteUser/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    if current_user.role != 'Admin' or not has_permission(current_user.id, "Manage Users"):
        flash("Access denied.", "error")
        return redirect(url_for("dashboard"))

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM rbac.doctor WHERE user_Id = %s", (user_id,))
            cur.execute("DELETE FROM rbac.nurse WHERE user_Id = %s", (user_id,))
            cur.execute("DELETE FROM rbac.patient WHERE user_Id = %s", (user_id,))
            cur.execute("DELETE FROM critical.doctor_priv_key WHERE doctor_id = %s", (user_id,))
            cur.execute("DELETE FROM critical.doctor_pub_key WHERE doctor_id = %s", (user_id,))
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

    return redirect(url_for("admin.view_users"))


@adm_bp.route("/createAccount", methods=["GET", "POST"])
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
                # hashed_pw = generate_password_hash(password) (old method using werkzeug)
                hashed_pw, salt = bcrypt_hash(password)
                cur.execute("INSERT INTO user (username, email, password,salt) VALUES (%s, %s, %s,%s)",
                            (username, email, hashed_pw, salt))
                user_id = cur.lastrowid

                # Insert into userrole table
                cur.execute("INSERT INTO userrole (user_Id, role_Id) VALUES (%s, %s)", (user_id, role_id))

                # Insert into staff table
                if role_name == "Doctor":
                    cur.execute("""INSERT INTO rbac.doctor (user_Id, first_name, last_name, age, gender)
                                   VALUES (%s, %s, %s, %s, %s)""",
                                (user_id, first_name, last_name, int(age), gender))
                    encrypted_rsa_key, rsa_public_key = create_encrypted_RSA_key()
                    cur.execute("""INSERT INTO critical.doctor_priv_key (doctor_id, private_enc_key, kek_id)
                                    VALUES (%s, %s, %s)""", (user_id, encrypted_rsa_key, 2))
                    cur.execute("""INSERT INTO critical.doctor_pub_key (doctor_id, public_key)
                                    VALUES (%s, %s)""", (user_id, rsa_public_key))
                    
                elif role_name == "Nurse":
                    cur.execute("""INSERT INTO rbac.nurse (user_Id, first_name, last_name, age, gender)
                                   VALUES (%s, %s, %s, %s, %s)""",
                                (user_id, first_name, last_name, int(age), gender))
                    
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
@adm_bp.route("/admin/viewLogs")
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
    for log in logs:
        log['action'] = decrypt_admin_log(log['action'])

    
    return render_template("admin_viewLogs.html", logs=logs)