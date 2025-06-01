import os
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

# 1. DIRECTORY CONFIGURATION
#
#   └── html/   → Jinja templates (index.html, login.html, etc.)
#   └── static/ → Static assets (CSS, JS, images)
project_root   = os.path.dirname(os.path.abspath(__file__))
html_folder    = os.path.join(project_root, "html")
static_folder  = os.path.join(project_root, "static")

# 2. CREATE FLASK APP WITH CUSTOM STATIC/TEMPLATE PATHS
app = Flask(
    __name__,
    template_folder=html_folder,
    static_folder=static_folder,
    static_url_path="/static"  # Files are accessed at /static/...
)

# 3. SECRET KEY & DATABASE CONFIGURATION
app.secret_key = os.getenv("FLASK_SECRET_KEY", "ssd-team-22-project")

login_manager = LoginManager(app)
login_manager.login_view = "login"  

app = Flask(__name__, template_folder=html_folder, static_folder=static_folder, static_url_path="/static")
app.secret_key = os.getenv("FLASK_SECRET_KEY", "ssd-team-22-project")

# Need to hide this somehow someway maybe in another db
# Database Connection (MySQL)
def get_db():
    return pymysql.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        # Change pw to what u set ur localhost pw
        password=os.getenv("DB_PASSWORD", "admin"),
        # Change to whatever you call ur schema
        database=os.getenv("DB_NAME", "rbac"),
        cursorclass=pymysql.cursors.DictCursor
    )

login_manager = LoginManager(app)
login_manager.login_view = "login"

# User Class
class User(UserMixin):
    def __init__(self, user_Id, username, password, role):
    # def __init__(self, user_Id, username, password):
        self.id = user_Id
        self.username = username
        self.password = password
        # fetched from userrole + role table
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

# Home page — serves html/index.html
@app.route("/")
def serve_index():
    return render_template("index.html")

# Run this to test ur db connection
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

# Just a simple register for now security stuff worry ltr
@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "")
        password = request.form.get("password", "")
        role_name = request.form.get("role", "").strip()

        # if not username or not password or not role_name:
        #     flash("All fields are required.", "error")
        #     return render_template("register.html")

        conn = get_db()
        try:
            with conn.cursor() as cur:
                # Check if user exists
                cur.execute("SELECT 1 FROM user WHERE username = %s", (username,))
                if cur.fetchone():
                    flash("Username already exists.", "error")
                    return render_template("register.html")
                
                cur.execute("SELECT role_Id FROM role WHERE role_name = %s", (role_name,))
                roleresult = cur.fetchone()
                role_id = roleresult['role_Id']
                
                hashed_pw = generate_password_hash(password)

                # Insert user
                cur.execute(
                    "INSERT INTO user (username, email, password) VALUES (%s, %s, %s)",
                    (username, email, hashed_pw)
                )

                # Get auto-incremented user ID
                user_id = cur.lastrowid
                
                # Assign role
                cur.execute("INSERT INTO userrole (user_Id, role_Id) VALUES (%s, %s)", (user_id, role_id))

                conn.commit()
                flash("Registration successful. Please log in.", "success")
                return redirect(url_for("login"))
        except Exception as e:
            conn.rollback()
            flash("Error registering user.", "error")
            print("Registration error:", e)  # 👈 Add this line
        finally:
            conn.close()

    return render_template("register.html")

# Same for login
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
            print("login successful")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password.", "error")

    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)
