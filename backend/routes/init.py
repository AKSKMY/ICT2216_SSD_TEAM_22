# from .authorisation_route import auth_bp
from .doctor_route import doctor_bp
from .nurse_route import nurse_bp
from .admin_route import adm_bp
from .patient_route import patient_bp


def register_blueprints(app):
    # app.register_blueprint(auth_bp)
    app.register_blueprint(doctor_bp)
    app.register_blueprint(nurse_bp)
    app.register_blueprint(adm_bp)
    app.register_blueprint(patient_bp)

