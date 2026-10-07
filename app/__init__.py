from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import text
import logging
import os
from datetime import timedelta

db = SQLAlchemy()
csrf = CSRFProtect()

# Verrou applicatif Postgres : sérialise la création des tables entre les workers gunicorn.
_DB_INIT_LOCK = 727272


def _require_env(name):
    value = os.getenv(name)
    if not value:
        raise RuntimeError(
            f"La variable d'environnement {name} est manquante. "
            "Copiez .env.example en .env et renseignez-la."
        )
    return value


def _init_db(app):
    """Crée les tables manquantes ; sûr quand plusieurs workers démarrent en même temps."""
    with app.app_context():
        with db.engine.begin() as conn:
            if conn.dialect.name == 'postgresql':
                conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _DB_INIT_LOCK})
            db.metadata.create_all(conn)


def create_app():
    logging.basicConfig(level=os.getenv('LOG_LEVEL', 'INFO'), format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    app = Flask(__name__)

    app.config['SECRET_KEY'] = _require_env('SECRET_KEY')

    # Force psycopg2 (driver installé via psycopg2-binary)
    raw_uri = _require_env('DATABASE_URL')
    if raw_uri.startswith('postgresql+psycopg://'):
        raw_uri = raw_uri.replace('postgresql+psycopg://', 'postgresql+psycopg2://', 1)
    elif raw_uri.startswith('postgresql://'):
        raw_uri = raw_uri.replace('postgresql://', 'postgresql+psycopg2://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = raw_uri

    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    # Sécurisé par défaut : ne passer SESSION_COOKIE_SECURE=false que pour un test local en HTTP.
    app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'true').lower() != 'false'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=4)

    db.init_app(app)
    csrf.init_app(app)

    from app.routes import bp
    app.register_blueprint(bp)

    from app.cli import register_cli
    register_cli(app)

    _init_db(app)

    return app
