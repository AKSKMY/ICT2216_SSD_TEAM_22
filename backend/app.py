import os
from dotenv import load_dotenv
load_dotenv()  # loads .env file automatically
import pymysql

from flask import (
    Flask, send_from_directory, render_template,
    request, redirect, url_for, flash
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import (
    LoginManager, UserMixin, login_user,
    logout_user, login_required, current_user
)
from config import DevelopmentConfig, ProductionConfig


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

# Decide which config to load based on FLASK_ENV env variable
env = os.getenv("FLASK_ENV", "development").lower()
if env == "production":
    app.config.from_object(ProductionConfig)
else:
    app.config.from_object(DevelopmentConfig)

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
        cursorclass=pymysql.cursors.DictCursor
    )

# ───────────────────────────────────────────────────────
# USER MODEL
# ───────────────────────────────────────────────────────
class User(UserMixin):
    def __init__(self, user_Id, username, password, role):
        self.id = user_Id
        self.username = username
        self.password = password
        self.role = role

    def check_password(self, plain_password):
        return check_password_hash(self.password, plain_password)

    def get_id(self):
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("""
            SELECT u.user_Id, u.username, u.password, r.role_name AS role
            FROM user u
            JOIN userrole ur ON u.user_Id = ur.user_Id
            JOIN role r ON ur.role_Id = r.role_Id
            WHERE u.user_Id = %s
        """, (user_id,))
        row = cur.fetchone()
    conn.close()
    if row:
        return User(**row)
    return None

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
        return f"MySQL connected! Result: {result}"
    except Exception as e:
        return f"MySQL connection failed: {e}"

@app.route("/")
def serve_index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "")
        password = request.form.get("password", "")

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

                hashed_pw = generate_password_hash(password)

                cur.execute(
                    "INSERT INTO user (username, email, password) VALUES (%s, %s, %s)",
                    (username, email, hashed_pw)
                )

                user_id = cur.lastrowid

                cur.execute("INSERT INTO userrole (user_Id, role_Id) VALUES (%s, %s)", (user_id, role_id))

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
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT u.user_Id, u.username, u.password, r.role_name AS role
                FROM user u
                JOIN userrole ur ON u.user_Id = ur.user_Id
                JOIN role r ON ur.role_Id = r.role_Id
                WHERE u.username = %s
            """, (username,))
            row = cur.fetchone()
        conn.close()

        if row and check_password_hash(row["password"], password):
            user = User(**row)
            login_user(user)
            if row["role"] == "Patient":
                return redirect(url_for("dashboard"))
            elif row["role"] == "Admin":
                return redirect(url_for("view_users"))
            elif row["role"] == "Doctor":
                return redirect(url_for("dashboard"))
            elif row["role"] == "Nurse":
                return redirect(url_for(""))

        else:
            flash("Invalid username or password.", "error")

    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

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
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        role_name = request.form.get("role", "").strip()

        if not username or not email or not password or not role_name:
            flash("All fields are required.", "error")
            return render_template("admin_createAccount.html")

        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM user WHERE username = %s", (username,))
                if cur.fetchone():
                    flash("Username already exists.", "error")
                    return render_template("admin_createAccount.html")

                cur.execute("SELECT role_Id FROM role WHERE role_name = %s", (role_name,))
                role_row = cur.fetchone()
                if not role_row:
                    flash("Invalid role selected.", "error")
                    return render_template("admin_createAccount.html")
                role_id = role_row["role_Id"]

                hashed_pw = generate_password_hash(password)
                cur.execute("INSERT INTO user (username, email, password) VALUES (%s, %s, %s)",
                            (username, email, hashed_pw))
                user_id = cur.lastrowid
                cur.execute("INSERT INTO userrole (user_Id, role_Id) VALUES (%s, %s)",
                            (user_id, role_id))
                conn.commit()
                flash("Staff account created successfully.", "success")
        except Exception as e:
            conn.rollback()
            flash("Error creating account.", "error")
            print("Create account error:", e)
        finally:
            conn.close()

    return render_template("admin_createAccount.html")

@app.route("/admin/viewLogs")
@login_required
def view_logs():
    return render_template("admin_viewLogs.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug_mode = app.config.get("DEBUG", False)
    app.run(debug=debug_mode, host="0.0.0.0", port=port)
