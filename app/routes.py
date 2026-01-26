from flask import Blueprint, render_template, request, redirect, url_for
from app.services.scanner import analyze_target
from app.services.ai import generate_report
from app.models import db, Audit

bp = Blueprint('main', __name__)

@bp.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        domain = request.form.get('domain')
        if not domain: return redirect(url_for('main.index'))
            
        scan_res = analyze_target(domain)
        ai_res = generate_report(scan_res)
        
        # --- CALCUL DU SCORE DE FOU ---
        # On commence à 50/100 (la moyenne)
        current_score = 50
        
        # On lit les détails générés par le scanner
        details = scan_res.get("score_details", [])
        
        for item in details:
            # On extrait les points (ex: "+20 pts" ou "-10 pts")
            try:
                points = int(item.split(" ")[0].replace("pts:", ""))
                current_score += points
            except:
                pass

        # Plafond et Plancher (0 à 100)
        current_score = max(0, min(100, current_score))
        
        # Attribution de la Lettre
        if current_score >= 90: letter = "A"
        elif current_score >= 80: letter = "B"
        elif current_score >= 60: letter = "C"
        elif current_score >= 40: letter = "D"
        else: letter = "F"

        # Sauvegarde
        audit = Audit(
            domain=domain,
            scan_data=scan_res,
            ai_report=ai_res,
            score=letter # On sauvegarde la lettre
        )
        # Astuce : On peut stocker le score numérique dans scan_data pour l'afficher
        audit.scan_data['numeric_score'] = current_score
        
        db.session.add(audit)
        db.session.commit()
        
        return redirect(url_for('main.dashboard', audit_id=audit.id))
        
    return render_template('index.html')

@bp.route('/dashboard/<int:audit_id>')
def dashboard(audit_id):
    audit = Audit.query.get_or_404(audit_id)
    return render_template('dashboard.html', audit=audit)