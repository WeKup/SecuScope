FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Dépendances système pour Postgres
RUN apt-get update && apt-get install -y --no-install-recommends libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Utilisateur non-root : un RCE dans l'app ne donne pas root dans le conteneur
RUN useradd --system --create-home --uid 10001 appuser && chown -R appuser:appuser /app

# /health répond sans authentification (voir app/routes.py)
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)" || exit 1

EXPOSE 8000

USER appuser

# Le conteneur écoute sur 0.0.0.0 (obligatoire pour la redirection de port Docker) ;
# l'exposition à l'hôte est restreinte à 127.0.0.1 dans docker-compose.yml.
CMD ["gunicorn", "-w", "3", "-b", "0.0.0.0:8000", "--timeout", "120", "app:create_app()"]
