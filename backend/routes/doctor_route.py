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

from function import has_permission, get_db, log_action, sign_medical_record, encrypt_medical_records, decrypt_AES_cipher, verify_signature

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
                   mr.patient_id, mr.doctor_id, mr.digital_signature,
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
            date = record["date"]
            if isinstance(date, datetime):
                date_str = date.strftime('%Y-%m-%d')
            elif isinstance(date, str):
                date_str = date.split(" ")[0]  # Fallback for string from DB
            else:
                date_str = str(date)
            print(f"is_valid values are: doctor_id: {record['doctor_id']}, diagnosis: {record['diagnosis']}, patient_id: {record['patient_id']}, date: {date_str}")
            is_valid = verify_signature(
                doctor_id=record["doctor_id"],
                diagnosis=record["diagnosis"],
                patient_id=record["patient_id"],
                date=date_str,  # Make sure this matches format used when signing
                b64_signature=record["digital_signature"]
            )
            record["verification_status"] = "✔️ Verified" if is_valid else "❌ Tampered"
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
            
            # Create digital signature
            digital_signature = sign_medical_record(current_user.id, diagnosis, patient_id, date_obj)
            encrypted_diagnosis = encrypt_medical_records(patient_id, diagnosis)
            
            # Insert medical record
            cur.execute("""
                INSERT INTO rbac.medical_record (patient_id, diagnosis, doctor_id, date, digital_signature)
                VALUES (%s, %s, %s, %s, %s)
            """, (patient_id, encrypted_diagnosis, current_user.id, date_obj, digital_signature))
            conn.commit()
            log_action(current_user.id, f"Doctor added a medical record for patient ID {patient_id}.")

        flash("Medical record added successfully!", "success")
        return redirect(url_for('doctor.doctor_view_patient_records', patient_id=patient_id))

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
        print(f"patient_id is {record['patient_id']}, record_date is {record_date}")
        digital_signature = sign_medical_record(current_user.id, diagnosis, record["patient_id"], record_date)
        encrypted_diagnosis = encrypt_medical_records(record["patient_id"], diagnosis)
            
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE rbac.medical_record
                SET diagnosis = %s, date = %s, digital_signature = %s
                WHERE record_id = %s AND doctor_id = %s
            """, (encrypted_diagnosis, date_str, digital_signature, record_id, current_user.id))
            conn.commit()
            log_action(current_user.id, f"Doctor edited medical record ID {record_id}.")

        flash("Medical record updated successfully!", "success")
        return redirect(url_for('doctor.doctor_view_patient_records', patient_id=record['patient_id']))

    return render_template('doctor_editRecord.html', record=record)
