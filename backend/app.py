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
# 1. DIRECTORY CONFIGURATION
#
#   └── html/   → Jinja templates (index.html, login.html, etc.)
#   └── static/ → Static assets (CSS, JS, images)
# ------------------------------------------------------------------------------
project_root   = os.path.dirname(os.path.abspath(__file__))
html_folder    = os.path.join(project_root, "html")
static_folder  = os.path.join(project_root, "static")

# ───────────────────────────────────────────────────────────────────────────────
# 2. CREATE FLASK APP WITH CUSTOM STATIC/TEMPLATE PATHS
# ------------------------------------------------------------------------------
app = Flask(
    __name__,
    template_folder=html_folder,
    static_folder=static_folder,
    static_url_path="/static"  # Files are accessed at /static/...
)

# ───────────────────────────────────────────────────────────────────────────────
# 3. SECRET KEY & DATABASE CONFIGURATION
# ------------------------------------------------------------------------------
app.secret_key = os.getenv("FLASK_SECRET_KEY", "ssd-team-22-project")

# Use env DATABASE_URL (e.g. in Docker), fallback to local SQLite for dev
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL",
    "sqlite:///users.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# ───────────────────────────────────────────────────────────────────────────────
# 4. SET UP DATABASE AND LOGIN MANAGER
# ------------------------------------------------------------------------------
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"  # redirects here if @login_required fails

# ───────────────────────────────────────────────────────────────────────────────
# 5. USER MODEL: includes role & password hashing methods
# ------------------------------------------------------------------------------
class User(UserMixin, db.Model):
    __tablename__ = "users"

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role          = db.Column(db.String(20), nullable=False)  # 'admin' / 'doctor' / 'user'

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
# 6. INITIALISE DB TABLES (for dev convenience)
# ------------------------------------------------------------------------------
with app.app_context():
    db.create_all()

# ───────────────────────────────────────────────────────────────────────────────
# 7. ROUTES
# ------------------------------------------------------------------------------

# Home page — serves html/index.html
@app.route("/")
def serve_index():
    return render_template("index.html")

# ───── Registration ─────
@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role     = request.form.get("role", "")

        # 1) Validate required fields
        if not username or not password or not role:
            flash("All fields are required.", "error")
            return render_template("register.html")

        # 2) Validate role
        if role not in ["admin", "doctor", "user"]:
            flash("Invalid role selected.", "error")
            return render_template("register.html")

        # 3) Ensure username is unique
        if User.query.filter_by(username=username).first():
            flash(f'Username "{username}" is already taken.', "error")
            return render_template("register.html")

        # 4) Create user
        new_user = User(username=username, role=role)
        new_user.set_password(password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))
        except Exception:
            db.session.rollback()
            flash("There was an error creating your account. Please try again.", "error")
            return render_template("register.html")

    return render_template("register.html")

# ───── Login ─────
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

    return render_template("login.html")

# ───── Dashboard ─────
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user)

# ───── Logout ─────
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# ───────────────────────────────────────────────────────────────────────────────
# 8. RUN FLASK SERVER (in dev mode)
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)
