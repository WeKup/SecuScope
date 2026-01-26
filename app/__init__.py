from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect 
import os

db = SQLAlchemy()
csrf = CSRFProtect() 
def create_app():
    app = Flask(__name__)
    
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


    if not app.config['SECRET_KEY']:
        raise RuntimeError("La variable d'environnement SECRET_KEY est manquante. Renommez .env.example en .env et définissez une clé.")

    db.init_app(app)
    csrf.init_app(app)

    from app.routes import bp
    app.register_blueprint(bp)

    return app