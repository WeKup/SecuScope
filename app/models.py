from app import db
from datetime import datetime

class Audit(db.Model):
    __tablename__ = 'audits'
    
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Stockage des résultats
    scan_data = db.Column(db.JSON)  # Contient SSL, Headers, WAF détecté, IP
    ai_report = db.Column(db.JSON)  # Le rapport GPT
    score = db.Column(db.String(2)) # A, B, C...