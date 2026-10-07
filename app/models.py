from app import db
from datetime import datetime
from werkzeug.security import check_password_hash, generate_password_hash


class User(db.Model):
    """Compte d'accès à l'application. Créé uniquement via `flask create-user` (pas d'inscription)."""
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Audit(db.Model):
    __tablename__ = 'audits'
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # Stockage des résultats
    scan_data = db.Column(db.JSON)  # Contient SSL, Headers, WAF détecté, IP
    ai_report = db.Column(db.JSON)  # Le rapport GPT
    score = db.Column(db.String(2)) # A, B, C...

    # Ajouts de sécurité et metric
    numeric_score = db.Column(db.Integer, default=0)
    session_id = db.Column(db.String(64))
