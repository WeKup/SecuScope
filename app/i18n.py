"""Internationalisation minimale : anglais par défaut, français en option, sans dépendance.

Les textes source (templates, routes) sont écrits en anglais ; FR les traduit. Les libellés
stockés en base par le scanner/scoring sont en français (anciens audits compris) : le filtre
`stored` les traduit à l'affichage, jamais à l'écriture, pour ne pas toucher aux invariants.
"""
from urllib.parse import urlencode

from flask import has_request_context, request

from app.translations import FR, STORED_EN, STORED_EN_PATTERNS

SUPPORTED = ("en", "fr")
DEFAULT_LANG = "en"
LANG_COOKIE = "lang"
LANG_COOKIE_MAX_AGE = 365 * 24 * 3600
LANG_NAMES = {"en": "English", "fr": "Français"}
# Nom de la langue tel qu'injecté dans le prompt du LLM (qui lui est écrit en français).
PROMPT_LANGUAGE = {"en": "anglais", "fr": "français"}


def get_lang():
    """Langue de la requête courante : cookie valide, sinon anglais."""
    if has_request_context():
        lang = request.cookies.get(LANG_COOKIE)
        if lang in SUPPORTED:
            return lang
    return DEFAULT_LANG


def tr(text, **values):
    """Traduit `text` (anglais) dans la langue courante ; texte inconnu = anglais tel quel.

    `values` remplace les `%(nom)s` du texte. Sans valeurs, aucun formatage (un « % » littéral reste intact)."""
    out = FR.get(text, text) if get_lang() == "fr" else text
    return out % values if values else out


def trn(singular, plural, n, **values):
    """Singulier/pluriel : `n` est aussi disponible comme `%(n)s`."""
    many = n > 1 if get_lang() == "fr" else n != 1
    return tr(plural if many else singular, n=n, **values)


def stored(value):
    """Libellé stocké en français (scanner, scoring) -> langue courante. Inconnu = inchangé."""
    text = str(value) if value is not None else ""
    if get_lang() == "fr":
        return text
    if text in STORED_EN:
        return STORED_EN[text]
    for pattern, repl in STORED_EN_PATTERNS:
        if pattern.match(text):
            return pattern.sub(repl, text)
    return text


def lang_url(code):
    """URL de la page courante avec ?lang=<code> (le before_request pose le cookie puis nettoie l'URL)."""
    args = {k: v for k, v in request.args.items() if k != "lang"}
    args["lang"] = code
    return f"{request.path}?{urlencode(args)}"


def clean_url():
    """URL de la page courante sans le paramètre lang."""
    args = [(k, v) for k, v in request.args.items(multi=True) if k != "lang"]
    return f"{request.path}?{urlencode(args)}" if args else request.path
