from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import (
    LoginManager, UserMixin, login_user,
    logout_user, login_required, current_user
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
from function import has_permission, get_db, decrypt_AES_cipher, verify_signature
from flask_mail import Mail, Message
import pymysql

patient_bp = Blueprint('patient', __name__, url_prefix='/patient')


# Patient - View Medical Records
@patient_bp.route('/user/patientRecords')
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
            SELECT mr.record_id, mr.diagnosis, mr.date, mr.doctor_id, mr.digital_signature,
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
            is_valid = verify_signature(
                doctor_id=record["doctor_id"],
                diagnosis=record["diagnosis"],
                patient_id=patient_id,
                date=str(record["date"]),  # Make sure this matches format used when signing
                b64_signature=record["digital_signature"]
            )
            record["verification_status"] = "✔️ Verified" if is_valid else "❌ Tampered"
    return render_template('medicalRecord.html', records=records)