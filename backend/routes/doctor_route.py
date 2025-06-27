from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import (
    LoginManager, UserMixin, login_user,
    logout_user, login_required, current_user
)
from datetime import datetime, date, timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
import pymysql

from backend.function import has_permission, get_db, log_action

doctor_bp = Blueprint('doctor', __name__, url_prefix='/doctor')


# Doctor - View patients
@doctor_bp.route("/doctor/viewPatients", methods=["GET", "POST"])
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
@doctor_bp.route('/doctor/patientRecords/<int:patient_id>')
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

    return render_template("medicalRecord.html", records=records, patient_id=patient_id)


# Doctor - Add Medical Records
@doctor_bp.route('/doctor/addRecord/<int:patient_id>', methods=['GET', 'POST'])
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
@doctor_bp.route('/doctor/editRecord/<int:record_id>', methods=['GET', 'POST'])
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

# Doctor - Add Patients
@doctor_bp.route('/doctor/addPatient', methods=['GET', 'POST'])
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
            return redirect(request.url)

        # Validate user_id is integer and exists in patient_users
        try:
            user_id_int = int(user_id)
        except ValueError:
            flash("Invalid user selection.", "error")
            return redirect(request.url)

        # Check if user_id is in patient_users list (to prevent tampering)
        if not any(u['user_Id'] == user_id_int for u in patient_users):
            flash("Selected user is invalid or already a patient.", "error")
            return redirect(request.url)

        # Validate gender
        valid_genders = {'Male', 'Female', 'Other'}
        if gender not in valid_genders:
            flash("Invalid gender selected.", "error")
            return redirect(request.url)
        gender = gender if gender else None

        # Validate date_of_birth
        if dob:
            try:
                dob_date = datetime.strptime(dob, '%Y-%m-%d').date()
                today = datetime.today().date()
                if dob_date > today:
                    flash("Date of birth cannot be in the future.", "error")
                    return redirect(request.url)
            except ValueError:
                flash("Invalid date of birth format.", "error")
                return redirect(request.url)
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
