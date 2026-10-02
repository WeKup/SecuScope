from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect 
import os
from datetime import timedelta

db = SQLAlchemy()
csrf = CSRFProtect() 
def create_app():
    app = Flask(__name__)
    
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

    # Force psycopg2 (driver installé via psycopg2-binary)
    raw_uri = os.getenv('DATABASE_URL', '')
    if raw_uri.startswith('postgresql+psycopg://'):
        raw_uri = raw_uri.replace('postgresql+psycopg://', 'postgresql+psycopg2://', 1)
    elif raw_uri.startswith('postgresql://'):
        raw_uri = raw_uri.replace('postgresql://', 'postgresql+psycopg2://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = raw_uri

    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=4)


    if not app.config['SECRET_KEY']:
        raise RuntimeError("La variable d'environnement SECRET_KEY est manquante. Renommez .env.example en .env et définissez une clé.")

    db.init_app(app)
    csrf.init_app(app)

    from app.routes import bp
    app.register_blueprint(bp)

    return app
