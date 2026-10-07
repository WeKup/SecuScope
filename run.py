"""Point d'entrée de développement local (python run.py). En production : gunicorn (voir Dockerfile)."""
import os

from app import create_app

app = create_app()

if __name__ == '__main__':
    # Debug désactivé par défaut ; FLASK_DEBUG=1 pour le développement uniquement.
    app.run(host='127.0.0.1', port=5000, debug=os.getenv('FLASK_DEBUG') == '1')
