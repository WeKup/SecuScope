from flask import Blueprint, render_template, request, redirect, url_for, flash
import validators

from app.services.scanner import analyze_target
from app.services.ai import generate_report
from app.services.scoring import calculate_trust_score  
from app.models import db, Audit

bp = Blueprint('main', __name__)

@bp.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        domain = request.form.get('domain', '').strip()
        
        if not domain:
            return redirect(url_for('main.index'))
            
        if not validators.domain(domain):
            return render_template('index.html', error="Domaine invalide")

    
        scan_res = analyze_target(domain)
        ai_res = generate_report(scan_res)
        score_data = calculate_trust_score(scan_res)
        
        scan_res['numeric_score'] = score_data['numeric']

        audit = Audit(
            domain=domain,
            scan_data=scan_res,
            ai_report=ai_res,
            score=score_data['letter']
        )
        
        db.session.add(audit)
        db.session.commit()
        
        return redirect(url_for('main.dashboard', audit_id=audit.id))
        
    return render_template('index.html')

@bp.route('/dashboard/<int:audit_id>')
def dashboard(audit_id):
    audit = Audit.query.get_or_404(audit_id)
    return render_template('dashboard.html', audit=audit)