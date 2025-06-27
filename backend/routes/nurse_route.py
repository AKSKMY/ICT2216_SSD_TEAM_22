from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import (
    LoginManager, UserMixin, login_user,
    logout_user, login_required, current_user
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
from flask_mail import Mail, Message
import pymysql

nurse_bp = Blueprint('nurse', __name__, url_prefix='/nurse')


# Nurse - View patients
@nurse_bp.route("/nurse/viewPatients", methods=["GET", "POST"])
@login_required
def nurse_view_patients():
    if current_user.role != 'Nurse' or not has_permission(current_user.id, "View Medical Records"):
        flash("Access denied.", "error")
        return redirect(url_for("dashboard"))

    search_query = request.args.get("search", "").strip()
    if search_query and not re.match(r"^[a-zA-Z\s\-']{1,50}$", search_query):
        flash("Invalid characters in search. Only letters and basic punctuation are allowed.", "error")
        return redirect(url_for("nurse_view_patients"))

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

# Nurse - View patients
@nurse_bp.route('/nurse/patientRecords/<int:patient_id>')
@login_required
def nurse_view_patient_records(patient_id):
    if current_user.role != 'Nurse' or not has_permission(current_user.id, "View Medical Records"):
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
            WHERE mr.patient_id = %s
            ORDER BY mr.date DESC
        """, (patient_id,))
        records = cur.fetchall()

    return render_template("medicalRecord.html", records=records, patient_id=patient_id)
