import os
from dotenv import load_dotenv
load_dotenv()  # loads .env file automatically
import pymysql
from datetime import datetime, date

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
        port=3306,
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
        # User Table
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "")
        password = request.form.get("password", "")

        # Patient Table
        first_name = request.form.get("first_name", "")
        last_name = request.form.get("last_name", "")
        gender = request.form.get("gender", "")
        date_of_birth_str = request.form.get("date_of_birth")
        age = request.form.get('age', '').strip()

        # Validate gender
        valid_genders = {'Male', 'Female', 'Other'}
        if gender not in valid_genders:
            flash("Invalid gender selected.", "error")
            return redirect(request.url)
        gender = gender if gender else None

        # Validate date_of_birth
        if date_of_birth_str:
            try:
                dob_date = datetime.strptime(date_of_birth_str, '%Y-%m-%d').date()
                today = datetime.today().date()
                if dob_date > today:
                    flash("Date of birth cannot be in the future.", "error")
                    return redirect(request.url)
            except ValueError:
                flash("Invalid date of birth format.", "error")
                return redirect(request.url)
        else:
            dob_date = None

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
                cur.execute(
                    """
                    INSERT INTO patient (user_Id, first_name, last_name, gender, data_of_birth, age)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (user_id, first_name, last_name, gender, date_of_birth_str, age)
                )

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
            log_action(user.id, f"{user.role} '{user.username}' logged in.")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password.", "error")

    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    admin_data = None
    doctor_data = None

    if current_user.role == "Admin":
        conn = get_db()
        with conn.cursor() as cur:
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
        conn.close()

        admin_data = {
            "total_users": total_users,
            "total_doctors": role_counts.get("Doctor", 0),
            "total_nurses": role_counts.get("Nurse", 0),
            "total_patients": role_counts.get("Patient", 0),
        }
    elif current_user.role == "Doctor":
        conn = get_db()
        with conn.cursor(pymysql.cursors.DictCursor) as cur:
            # Count assigned patients
            cur.execute("""
                SELECT COUNT(*) AS total_patients
                FROM rbac.patient p
                JOIN rbac.medical_record mr ON p.user_Id = mr.patient_id
                WHERE mr.doctor_id = %s
            """, (current_user.id,))
            total_patients = cur.fetchone()['total_patients']

            # Recent records added by this doctor
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
        conn.close()

        doctor_data = {
            "total_patients": total_patients,
            "recent_records": recent_records
        }

    return render_template("dashboard.html", admin_data=admin_data, doctor_data=doctor_data)


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

        # Basic validation
        if not username or not email or not password or not role_name:
            flash("All fields are required.", "error")
            return render_template("admin_createAccount.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("admin_createAccount.html")

        if "@" not in email or "." not in email.split("@")[-1]:
            flash("Invalid email format.", "error")
            return render_template("admin_createAccount.html")

        valid_roles = {"Doctor", "Nurse"}
        if role_name not in valid_roles:
            flash("Invalid role selected.", "error")
            return render_template("admin_createAccount.html")

        # Staff-specific validation
        if role_name in valid_roles:
            if not first_name or not last_name or not age or not gender:
                flash("All staff fields are required for Doctor/Nurse.", "error")
                return render_template("admin_createAccount.html")

            if not age.isdigit() or int(age) < 0:
                flash("Age must be a valid positive number.", "error")
                return render_template("admin_createAccount.html")

            if gender not in {"Male", "Female", "Other"}:
                flash("Invalid gender selected.", "error")
                return render_template("admin_createAccount.html")

            age = int(age)

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

                # Insert into user table
                hashed_pw = generate_password_hash(password)
                cur.execute("INSERT INTO user (username, email, password) VALUES (%s, %s, %s)",
                            (username, email, hashed_pw))
                user_id = cur.lastrowid

                # Insert into userrole table
                cur.execute("INSERT INTO userrole (user_Id, role_Id) VALUES (%s, %s)", (user_id, role_id))

                # Insert into staff table
                if role_name == "Doctor":
                    cur.execute("""INSERT INTO rbac.doctor (user_Id, first_name, last_name, age, gender)
                                   VALUES (%s, %s, %s, %s, %s)""",
                                (user_id, first_name, last_name, age, gender))
                elif role_name == "Nurse":
                    cur.execute("""INSERT INTO rbac.nurse (user_Id, first_name, last_name, age, gender)
                                   VALUES (%s, %s, %s, %s, %s)""",
                                (user_id, first_name, last_name, age, gender))

                conn.commit()
                flash(f"{role_name} account created successfully!", "success")
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


# Doctor - View patients
@app.route("/doctor/viewPatients", methods=["GET", "POST"])
@login_required
def view_patients():
    if current_user.role != 'Doctor' or not has_permission(current_user.id, "View Medical Records"):
        flash("Access denied.", "error")
        return redirect(url_for("dashboard"))

    search_query = request.args.get("search", "").strip()

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

    return render_template("doctor_viewPatients.html", users=users, search_query=search_query)

# Doctor - View Medical records
@app.route('/doctor/patientRecords/<int:patient_id>')
@login_required
def view_patient_records(patient_id):
    if current_user.role != 'Doctor' or not has_permission(current_user.id, "View Medical Records"):
        flash("Access denied.", "error")
        return redirect(url_for("dashboard"))

    conn = get_db()
    with conn.cursor(pymysql.cursors.DictCursor) as cur:  # Use DictCursor
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
            return redirect(request.url)

        # Validate and sanitize date
        try:
            date_obj = datetime.strptime(record_date, "%Y-%m-%d").date()
            if date_obj > date.today():
                flash("Date cannot be in the future.", "error")
                return redirect(request.url)
        except ValueError:
            flash("Invalid date format.", "error")
            return redirect(request.url)

        with conn.cursor() as cur:
            # Ensure patient exists
            cur.execute("SELECT 1 FROM rbac.patient WHERE user_Id = %s", (patient_id,))
            if not cur.fetchone():
                flash("Patient not found.", "error")
                return redirect(url_for("dashboard"))

            # Insert medical record
            cur.execute("""
                INSERT INTO rbac.medical_record (patient_id, diagnosis, doctor_id, date)
                VALUES (%s, %s, %s, %s)
            """, (patient_id, diagnosis, current_user.id, date_obj))
            conn.commit()
            log_action(current_user.id, f"Doctor added a medical record for patient ID {patient_id}.")

        flash("Medical record added successfully!", "success")
        return redirect(url_for('view_patient_records', patient_id=patient_id))

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

    if not record:
        flash("Medical record not found or access denied.", "error")
        return redirect(url_for("dashboard"))

    if request.method == 'POST':
        diagnosis = request.form.get('diagnosis', '').strip()
        date_str = request.form.get('date', '').strip()

        # Basic required fields check
        if not diagnosis or not date_str:
            flash("All fields are required.", "error")
            return redirect(request.url)

        # Validate date format
        try:
            record_date = datetime.strptime(date_str, '%Y-%m-%d').date()
            today = datetime.today().date()
            if record_date > today:
                flash("Date cannot be in the future.", "error")
                return redirect(request.url)
        except ValueError:
            flash("Invalid date format.", "error")
            return redirect(request.url)

        with conn.cursor() as cur:
            cur.execute("""
                UPDATE rbac.medical_record
                SET diagnosis = %s, date = %s
                WHERE record_id = %s AND doctor_id = %s
            """, (diagnosis, date_str, record_id, current_user.id))
            conn.commit()
            log_action(current_user.id, f"Doctor edited medical record ID {record_id}.")

        flash("Medical record updated successfully!", "success")
        return redirect(url_for('view_patient_records', patient_id=record['patient_id']))

    return render_template('doctor_editRecord.html', record=record)


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
