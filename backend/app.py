import os
from flask import (
    Flask,
    send_from_directory,
    render_template,
    request,
    redirect,
    url_for,
    flash
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user
)

# ───────────────────────────────────────────────────────────────────────────────
# 1. STATIC / TEMPLATE FOLDER CONFIGURATION
#
# We want:
#   •  to serve index.html (and any other static assets) from ../html
#   •  to load Jinja templates (register.html, login.html, dashboard.html, etc.) from ../html
#
# “project_root” is the directory containing this app.py (i.e. backend/).
# “html_folder” points to the sibling "html" directory.
project_root = os.path.dirname(os.path.abspath(__file__))
html_folder  = os.path.normpath(os.path.join(project_root, "../html"))

app = Flask(
    __name__,
    template_folder=html_folder,   # Jinja templates live in ../html
    static_folder=html_folder,     # any static file (index.html, CSS, JS, etc.) also in ../html
    static_url_path=""             # serve those files at “/…”
)

# ───────────────────────────────────────────────────────────────────────────────
# 2. SECRET KEY & DATABASE CONFIGURATION
#
# We'll read DATABASE_URL from env (provided by Docker‐Compose), or fallback to SQLite.
app.secret_key = os.getenv("FLASK_SECRET_KEY", "ssd-team-22-project")

database_url = os.getenv(
    "DATABASE_URL",
    "sqlite:///users.db"   # fallback if you run locally without Docker
)
app.config["SQLALCHEMY_DATABASE_URI"]        = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# ───────────────────────────────────────────────────────────────────────────────
# 3. SET UP SQLALCHEMY & FLASK-LOGIN
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


# ───────────────────────────────────────────────────────────────────────────────
# 4. USER MODEL (with “role”)
class User(UserMixin, db.Model):
    __tablename__ = "users"

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role          = db.Column(db.String(20), nullable=False)  # must be 'admin' / 'doctor' / 'user'

    def set_password(self, plain_password):
        self.password_hash = generate_password_hash(plain_password)

    def check_password(self, plain_password):
        return check_password_hash(self.password_hash, plain_password)

    def get_id(self):
        return str(self.id)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ───────────────────────────────────────────────────────────────────────────────
# 5. AUTO-CREATE TABLES (only the first time; for production, use migrations)
with app.app_context():
    db.create_all()


# ───────────────────────────────────────────────────────────────────────────────
# 6. ROUTES
#
#  6a) Serve index.html at “/”
#  6b) /register, /login, /dashboard, /logout

@app.route("/")
def serve_index():
    """
    This will serve html/index.html (and any other file in ../html)
    if you go to http://<host>:<port>/
    """
    return send_from_directory(app.static_folder, "index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role     = request.form.get("role", "")

        # 1) Basic validation: all fields required
        if not username or not password or not role:
            flash("All fields are required.", "error")
            return render_template("register.html")

        # 2) Enforce allowed roles
        if role not in ["admin", "doctor", "user"]:
            flash("Invalid role selected.", "error")
            return render_template("register.html")

        # 3) Check username uniqueness
        if User.query.filter_by(username=username).first():
            flash(f'Username "{username}" is already taken.', "error")
            return render_template("register.html")

        # 4) Create the new user, hash their password
        new_user = User(username=username, role=role)
        new_user.set_password(password)

        try:
            db.session.add(new_user)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash("There was an error creating your account. Please try again.", "error")
            return render_template("register.html")

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    # If GET, just show the registration form
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password.", "error")
            return render_template("login.html")

    # If GET, show login form
    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    """
    Renders dashboard.html, passing in current_user.
    The template can check current_user.role to show role‐specific content.
    """
    return render_template("dashboard.html", user=current_user)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# ───────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    # Debug=True for local development only; in production set False or remove.
    app.run(debug=True, host="0.0.0.0", port=port)
