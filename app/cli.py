"""Commandes CLI : la seule voie de création de compte (aucune inscription publique)."""
import click
import validators

from app import db
from app.models import User

MIN_PASSWORD_LENGTH = 8


def register_cli(app):
    @app.cli.command('create-user')
    @click.option('--email', required=True, help="Adresse e-mail (identifiant de connexion).")
    @click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True,
                  help="Mot de passe (demandé en saisie masquée s'il est omis).")
    def create_user(email, password):
        """Crée un compte, ou réinitialise le mot de passe s'il existe déjà."""
        email = email.strip().lower()
        if not validators.email(email):
            raise click.ClickException("Adresse e-mail invalide.")
        if len(password) < MIN_PASSWORD_LENGTH:
            raise click.ClickException(f"Mot de passe trop court (minimum {MIN_PASSWORD_LENGTH} caractères).")

        user = User.query.filter_by(email=email).first()
        created = user is None
        if created:
            user = User(email=email)
            db.session.add(user)
        user.set_password(password)
        db.session.commit()
        click.echo(f"Compte {'créé' if created else 'mis à jour'} : {email}")
