import os
import logging
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, abort
from werkzeug.security import check_password_hash, generate_password_hash
import validators
from app.services.scanner import analyze_target
from app.services.ai import generate_report, is_valid_report, posture_signature
from app.services.scoring import calculate_trust_score  
from app.models import db, Audit, User
import uuid
from urllib.parse import urlparse


bp = Blueprint('main', __name__)
logger = logging.getLogger(__name__)

AI_CACHE_DAYS = 7            # fenêtre de réutilisation d'un rapport IA à posture identique
RECENT_SCAN_MINUTES = 10     # même session, même domaine : on affiche le scan récent au lieu d'en relancer un

ALLOWED_MODELS = {
    "gemini-2.5-flash",
    "gemini-2.5-flash-lite-preview-06-17",
    "gemini-1.5-flash",
}
DEFAULT_MODEL = "gemini-2.5-flash"
MAX_API_KEY_LENGTH = 256
MAX_EMAIL_LENGTH = 255
MAX_PASSWORD_LENGTH = 256

# Hash factice : on le vérifie quand l'e-mail est inconnu pour que le temps de réponse
# ne révèle pas quels comptes existent.
_DUMMY_HASH = generate_password_hash("secuscope-dummy-password")

# Seuls ces endpoints sont accessibles sans compte (les fichiers statiques ne passent pas par le blueprint).
PUBLIC_ENDPOINTS = {'main.login', 'main.health'}


@bp.before_request
def require_login():
    """Toute l'application est derrière connexion, sauf la page de login et /health."""
    if request.endpoint in PUBLIC_ENDPOINTS:
        return None
    user_id = session.get('user_id')
    if not user_id or db.session.get(User, user_id) is None:
        session.clear()
        return redirect(url_for('main.login'))
    return None


@bp.app_context_processor
def inject_ui_context():
    """Modèle IA effectif et origine de la clé, pour le header."""
    return {
        'current_model': session.get('user_model_id') or DEFAULT_MODEL,
        'own_key': bool(session.get('user_api_key')),
    }


def _server_api_key():
    return os.getenv('GOOGLE_API_KEY', '').strip()


def _ai_report_for(scan_res, domain):
    """Rapport IA pour ce scan : réutilisé si un audit récent du même domaine a la même posture, sinon
    généré par le modèle. L'audit (historique) est créé dans tous les cas : seul le TEXTE est mis en cache."""
    signature = posture_signature(scan_res)
    cutoff = datetime.utcnow() - timedelta(days=AI_CACHE_DAYS)
    candidates = (Audit.query
                  .filter(Audit.domain == domain, Audit.timestamp >= cutoff,
                          Audit.ai_report['posture_signature'].as_string() == signature)
                  .order_by(Audit.id.desc()).limit(5).all())
    for previous in candidates:
        if is_valid_report(previous.ai_report):
            logger.info("Rapport IA réutilisé pour %s (audit %s, même posture) : aucun appel Gemini", domain, previous.id)
            return {**previous.ai_report, 'reused_from': previous.id}

    logger.info("Rapport IA : appel Gemini pour %s (posture nouvelle ou sans rapport valide)", domain)
    report = generate_report(
        scan_res,
        api_key=session.get('user_api_key') or _server_api_key(),
        model_id=session.get('user_model_id') or DEFAULT_MODEL,
    )
    if is_valid_report(report):
        report['posture_signature'] = signature  # mémorisée avec le rapport, jamais affichée
    return report


def _recent_scan(domain):
    """Scan du même domaine par la même session il y a moins de RECENT_SCAN_MINUTES, ou None."""
    cutoff = datetime.utcnow() - timedelta(minutes=RECENT_SCAN_MINUTES)
    return (Audit.query
            .filter(Audit.domain == domain, Audit.session_id == session.get('session_id', ''),
                    Audit.timestamp >= cutoff)
            .order_by(Audit.id.desc()).first())

def normalize_domain(raw: str) -> str:
    """Extrait le domaine nu depuis une saisie libre :
    'https://example.com/path?q=1', 'example.com:443', 'EXAMPLE.com/' -> 'example.com'
    """
    raw = raw.strip()
    if not raw:
        return ""
    # urlparse a besoin d'un schéma pour peupler .netloc ; on en met un bidon si absent
    if "://" not in raw:
        raw = "//" + raw
    parsed = urlparse(raw, scheme="http")
    host = parsed.hostname or ""   # .hostname enlève déjà le port et le user:pass
    return host.lower().rstrip(".")


@bp.route('/health')
def health():
    return {"status": "ok"}, 200


@bp.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''
        api_key = (request.form.get('api_key') or '').strip()
        model_id = request.form.get('model_id', DEFAULT_MODEL)

        user = None
        if email and len(email) <= MAX_EMAIL_LENGTH and len(password) <= MAX_PASSWORD_LENGTH:
            user = User.query.filter_by(email=email).first()
        valid = user.check_password(password) if user else (check_password_hash(_DUMMY_HASH, password) and False)
        if not valid:
            return render_template('login.html', error="Identifiants invalides."), 401
        if len(api_key) > MAX_API_KEY_LENGTH:
            return render_template('login.html', error="Clé API invalide."), 400

        session.clear()  # nouvelle session : pas de fixation, historique cloisonné par connexion
        session.permanent = True
        session['user_id'] = user.id
        if model_id not in ALLOWED_MODELS:
            model_id = DEFAULT_MODEL
        session['user_model_id'] = model_id
        if api_key:  # surcharge optionnelle : sans elle, la clé serveur (GOOGLE_API_KEY) est utilisée
            session['user_api_key'] = api_key
        return redirect(url_for('main.index'))

    if session.get('user_id'):
        return redirect(url_for('main.index'))
    return render_template('login.html')

@bp.route('/scan', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        domain = normalize_domain(request.form.get('domain', ''))
        
        if not request.form.get('legal_consent'):
            return render_template('index.html', error="Vous devez certifier avoir l'autorisation de scanner ce domaine.")
            
        if not domain:
            return redirect(url_for('main.index'))
            
        if not validators.domain(domain):
            return render_template('index.html', error="Domaine invalide")
        
        if 'session_id' not in session:
            session['session_id'] = str(uuid.uuid4())

        # Anti double-scan involontaire : même domaine scanné par cette session il y a peu -> rapport existant.
        if request.form.get('force') != '1':
            recent = _recent_scan(domain)
            if recent is not None:
                return redirect(url_for('main.dashboard', audit_id=recent.id, recent=1))

        scan_res = analyze_target(domain)
        
        # Check pour faille SSRF renvoyée par le scanner
        if scan_res.get('error') == "PRIVATE_IP":
            flash("Action non autorisée : résolution vers une IP privée détectée.", "error")
            return redirect(url_for('main.index'))
            
        if scan_res.get('error') == "NXDOMAIN":
            flash(f"Le domaine '{domain}' est introuvable ou n'existe pas.", "error")
            return redirect(url_for('main.index'))
            
        score_data = calculate_trust_score(scan_res)
        if score_data['partial']:
            # Verdict partiel : on n'enregistre aucune note globale (ni lettre, ni /100) pour ne pas
            # polluer la courbe ; les clés numeric_score/score sont absentes, le prompt IA garde ses défauts.
            scan_res['partial'] = True
        else:
            scan_res['numeric_score'] = score_data['numeric']
            scan_res['score'] = score_data['letter']
        # score_details : vue dégradée "-N pts: ..." pour l'ancien dashboard ;
        # score_breakdown : le vrai détail par catégorie (futur front).
        scan_res['score_details'] = score_data['details']
        scan_res['score_breakdown'] = {k: score_data[k] for k in ('categories', 'infra_bonus', 'raw_score', 'cap')}
        ai_res = _ai_report_for(scan_res, domain)

        audit = Audit(
            domain=domain,
            scan_data=scan_res,
            ai_report=ai_res,
            score=score_data['letter'],
            numeric_score=score_data['numeric'],
            session_id=session.get('session_id', '')
        )
        db.session.add(audit)
        db.session.commit()
        return redirect(url_for('main.dashboard', audit_id=audit.id))
        
    # Lien « forcer un nouveau scan » : domaine prérempli, le consentement reste à cocher.
    prefill = normalize_domain(request.args.get('domain', ''))
    return render_template('index.html', prefill_domain=prefill if validators.domain(prefill) else '',
                           force=request.args.get('force') == '1')

HISTORY_LIMIT = 15

def _score_history(audit):
    """Scores des derniers scans du même domaine, dans la même session, jusqu'à `audit` inclus.
    Ordre chronologique ; le dernier point est l'audit affiché."""
    rows = (Audit.query
            .filter(Audit.domain == audit.domain,
                    Audit.session_id == audit.session_id,
                    Audit.id <= audit.id,
                    Audit.numeric_score.isnot(None))  # les scans partiels ne sont pas notés : hors courbe
            .order_by(Audit.id.desc())
            .limit(HISTORY_LIMIT)
            .all())
    return [
        {'date': r.timestamp.strftime('%d.%m %H:%M') if r.timestamp else '', 'score': int(r.numeric_score)}
        for r in reversed(rows)
    ]

@bp.route('/dashboard/<int:audit_id>')
def dashboard(audit_id):
    audit = Audit.query.get_or_404(audit_id)
    if audit.session_id != session.get('session_id'):
        abort(403)
    recent_notice = None
    if request.args.get('recent') and audit.timestamp:
        age = datetime.utcnow() - audit.timestamp
        if age <= timedelta(minutes=RECENT_SCAN_MINUTES):
            recent_notice = {'minutes': max(1, int(age.total_seconds() // 60))}
    return render_template('dashboard.html', audit=audit, score_history=_score_history(audit),
                           recent_notice=recent_notice)

@bp.route('/logout')
def logout():
    session.clear()
    flash("Vous êtes déconnecté.", "info")
    return redirect(url_for('main.login'))
