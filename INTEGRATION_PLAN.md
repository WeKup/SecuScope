# Plan d'integration - Partie 2 Scan DNS profond

## Objectif

Ajouter une Partie 2 dediee a un scan DNS profond, reservee aux utilisateurs `premium`, tout en conservant la Partie 1 intacte. La Partie 2 doit reprendre les conventions existantes de SecuScope: validation de domaine, consentement legal, journalisation via `score_details`, historique par `session_id`, stockage JSON en base et rendu sombre Tailwind.

Ce plan est volontairement non intrusif: aucune ligne de la Partie 1 ne doit etre modifiee. Les ajouts doivent se faire dans de nouveaux fichiers et par enregistrement additionnel de blueprint au niveau de l'application.

## 1. Analyse de la Partie 1 existante

### Entrees utilisateur

Le scan actuel est expose par `main.index` sur `/scan` dans `app/routes.py`.

Flux d'entree:

- `GET /scan`: rend le formulaire `app/templates/index.html`.
- `POST /scan`: lit `domain` depuis le formulaire.
- Le scan exige `legal_consent`.
- Le scan exige une session contenant `user_api_key`.
- Le domaine est nettoye avec `.strip()` puis valide avec `validators.domain(domain)`.
- Un `session_id` UUID est cree en session si absent.

La route ne recoit pas de JSON: l'interface actuelle est un formulaire HTML protege par CSRF Flask-WTF.

### Traitement reseau

Le traitement principal est orchestre par `analyze_target(domain)` dans `app/services/scanner.py`.

Etapes principales:

- Normalisation du domaine en minuscules.
- Resolution DNS A via `get_dns_info(domain)`.
- Collecte DNS minimale: IP, PTR, CNAME et NS.
- Protection SSRF: `is_safe_domain(ip)` refuse les IP privees.
- Gestion NXDOMAIN par retour structure `{ "error": "NXDOMAIN" }`.
- Execution parallele de deux analyses avec `ThreadPoolExecutor(max_workers=2)`:
  - `get_ssl_info(domain)` pour le certificat TLS et le port 443.
  - `get_http_info(target_url, dns_info, domain)` pour HTTPS, headers, cookies, WAF, serveur et technologies.
- Detection WAF en trois niveaux:
  - WafW00F si disponible.
  - Signatures passives depuis headers, cookies, body et signaux DNS.
  - Requete active legere de dernier recours.
- Kill-switch si echec critique HTTP/TLS: le score est force indirectement a 0 via details fortement negatifs.

La structure de retour nominale de `analyze_target()` est:

```json
{
  "domain": "example.com",
  "ip": "93.184.216.34",
  "ssl": {},
  "waf_detected": "Non detecte",
  "server": "Masque",
  "headers": {},
  "missing_headers": [],
  "cookies_security": [],
  "tech_stack": [],
  "score_details": []
}
```

Les erreurs importantes renvoyees par le scanner sont:

- `PRIVATE_IP`: resolution vers une IP privee ou non acceptable.
- `NXDOMAIN`: domaine inexistant ou resolution impossible assimilee a une erreur DNS.

### Scoring et logs

Le scoring est calcule par `calculate_trust_score(scan_results)` dans `app/services/scoring.py`.

La convention de logs est simple et doit etre conservee:

- Chaque element de `score_details` est une chaine lisible.
- Les impacts de score commencent par `+N pts` ou `-N pts`.
- Le calcul utilise une regex `^([+-]\d+)\s*pts`.
- Les details sans prefixe de score restent affichables mais n'impactent pas la note.
- Le score part de 50, puis est borne entre 0 et 100.
- La lettre finale est `A`, `B`, `C`, `D` ou `F`.

Pour la Partie 2, les nouveaux controles DNS doivent donc produire des messages du meme type, par exemple:

- `+10 pts: DNSSEC actif`
- `-15 pts: Enregistrement SPF absent`
- `-10 pts: DMARC en mode none`
- `+5 pts: MX redondants detectes`
- `Info: 4 sous-domaines exposes detectes`

### Stockage et historique

Le modele unique actuel est `Audit` dans `app/models.py`.

Champs existants:

- `id`: identifiant technique.
- `domain`: domaine scanne.
- `timestamp`: date UTC de creation.
- `scan_data`: JSON contenant les resultats techniques.
- `ai_report`: JSON contenant le rapport IA.
- `score`: lettre.
- `numeric_score`: score numerique.
- `session_id`: rattachement a la session Flask.

La route `/dashboard/<audit_id>` charge l'audit puis refuse l'acces si `audit.session_id != session.get('session_id')`.

Conclusion: l'historique actuel n'est pas rattache a un compte utilisateur persistant. Il est rattache a la session navigateur courante. La Partie 2 doit reprendre ce comportement si l'objectif est de rester compatible avec la Partie 1 sans migration immediate.

## 2. Analyse de l'authentification et des sessions

### Mecanisme actuel

L'application n'utilise pas JWT, OAuth, Flask-Login, table `User`, mot de passe, ni cookie applicatif maison.

Le mecanisme actuel est une session Flask signee par `SECRET_KEY`:

- `session['user_api_key']`: cle API Gemini saisie dans le formulaire de login.
- `session['user_model_id']`: modele Gemini selectionne.
- `session['session_id']`: UUID cree au premier scan pour isoler l'historique.

Le logout appelle `session.clear()`.

### Implications securite

Points forts actuels:

- CSRF active via `CSRFProtect`.
- Cookies de session signes par Flask.
- Les resultats dashboard sont isoles par `session_id`.
- La route de scan refuse l'execution sans `user_api_key`.

Limites actuelles:

- La session ne prouve pas une identite utilisateur durable.
- Le statut `premium` n'existe pas encore.
- L'API key Gemini est stockee cote session Flask. Selon la configuration Flask, cela peut etre stocke dans le cookie signe client; il faut eviter d'ajouter des donnees sensibles supplementaires.
- `session_id` protege l'historique contre l'acces direct, mais ne remplace pas une autorisation utilisateur forte.

### Strategie premium compatible sans toucher la Partie 1

Pour restreindre la Partie 2 aux utilisateurs `premium` sans modifier la Partie 1, ajouter un module d'autorisation dedie:

```text
app/auth/
  __init__.py
  premium.py
```

Responsabilite de `premium.py`:

- Lire le contexte existant de `session`.
- Exposer `is_authenticated_session()`.
- Exposer `is_premium_session()`.
- Exposer un decorateur `premium_required`.

Politique recommandee en phase 1:

- Authentifie si `session['user_api_key']` existe.
- Premium si `session['is_premium'] is True` ou si `session['plan'] == 'premium'`.
- En environnement de production, alimenter ce flag depuis un fournisseur externe ou une future table utilisateur, jamais depuis un champ de formulaire libre.

La Partie 2 utilisera uniquement `premium_required`; la Partie 1 gardera son comportement actuel.

## 3. Cartographie design et arborescence

### Arborescence actuelle

```text
app/
  __init__.py
  models.py
  routes.py
  services/
    ai.py
    scanner.py
    scoring.py
    signature.py
  templates/
    base.html
    login.html
    index.html
    dashboard.html
run.py
requirements.txt
Dockerfile
docker-compose.yml
```

### Themes et UI

L'application utilise Tailwind via CDN dans `app/templates/base.html`, pas une compilation Tailwind locale.

Conventions visuelles:

- Mode sombre global: `html.dark`, fond `#0f172a`, texte `#e2e8f0`.
- Palette dominante: `slate-*`, `blue-*`, `emerald-*`, avec alertes `red-*`, `yellow-*`, `orange-*`.
- Layout principal: `container mx-auto p-4`.
- Cartes: `bg-slate-800`, `border border-slate-700`, `rounded-xl`, `shadow-*`.
- Formulaires: `bg-slate-900`, `border-slate-700`, focus `border-blue-500` ou `ring-blue-500`.
- Feedback scan: loader CSS local et bouton qui passe en etat "Scan en cours...".
- Dashboard: grille `lg:grid-cols-3`, cartes d'analyse, radar Chart.js, details de score sous forme de liste.
- Iconographie: Font Awesome charge dans `base.html`, emojis utilises dans plusieurs templates.

### Consequence pour la Partie 2

La Partie 2 devrait ajouter des templates dedies sans changer ceux de la Partie 1:

```text
app/templates/dns_deep_scan.html
app/templates/dns_deep_dashboard.html
```

Ces templates doivent etendre `base.html` et reprendre:

- Les cartes `bg-slate-800 border border-slate-700/50 rounded-xl`.
- Les champs de formulaire `bg-slate-900 border-slate-700`.
- Les badges de statut `emerald`, `blue`, `yellow`, `red`.
- La liste `score_details` avec le meme parsing visuel `+` / `-`.
- Un bloc "Surface DNS" equivalent a "Surface d'Attaque".

## 4. Emplacement recommande de la nouvelle route API

### Principe

Ne pas etendre `app/routes.py`, car il porte deja la Partie 1. Creer un blueprint separe pour la Partie 2.

Nouvelle structure proposee:

```text
app/
  auth/
    __init__.py
    premium.py
  routes_dns.py
  services/
    dns_deep_scanner.py
    dns_scoring.py
  templates/
    dns_deep_scan.html
    dns_deep_dashboard.html
```

### Routes recommandees

Blueprint:

```python
dns_bp = Blueprint("dns_deep", __name__, url_prefix="/premium/dns")
```

Routes:

- `GET /premium/dns/scan`
  - Affiche le formulaire DNS profond.
  - Requiert `premium_required`.

- `POST /premium/dns/scan`
  - Formulaire HTML compatible CSRF.
  - Lit `domain` et `legal_consent`.
  - Valide avec `validators.domain`.
  - Cree `session_id` si absent.
  - Appelle `analyze_dns_deep(domain)`.
  - Calcule le score via la meme convention `score_details`.
  - Persiste un audit.
  - Redirige vers `/premium/dns/dashboard/<audit_id>`.

- `POST /premium/dns/api/scan`
  - API JSON pour automatisation future.
  - Requiert `premium_required`.
  - Requiert CSRF si appelee depuis navigateur avec session cookie, ou mecanisme token separe si usage machine-to-machine.
  - Retourne JSON structurel sans rendu HTML.

- `GET /premium/dns/dashboard/<audit_id>`
  - Charge l'audit.
  - Verifie `audit.session_id == session.get('session_id')`.
  - Verifie que l'audit correspond a un scan DNS profond.
  - Rend `dns_deep_dashboard.html`.

### Enregistrement du blueprint

L'enregistrement doit se faire dans `create_app()` en ajoutant le blueprint DNS. Comme la contrainte interdit de modifier la Partie 1, deux options propres existent:

Option A, recommandee a moyen terme:

- Modifier uniquement `app/__init__.py`, qui est le bootstrap applicatif, pas la logique Partie 1.
- Ajouter:

```python
from app.routes_dns import dns_bp
app.register_blueprint(dns_bp)
```

Option B, zero modification de fichiers existants:

- Creer une factory alternative `app/create_app_v2.py` ou `run_v2.py`.
- Elle importe `create_app()`, appelle la factory existante, puis enregistre `dns_bp`.
- Cette option respecte strictement "aucune ligne existante modifiee", mais impose de lancer l'application via un nouvel entrypoint.

Recommandation: utiliser l'option A si "Partie 1" signifie les fichiers de scan actuels (`routes.py`, `scanner.py`, templates existants). Utiliser l'option B si la contrainte signifie vraiment aucun fichier existant modifie.

## 5. Structure de donnees Partie 2

### Option de stockage compatible immediatement

Reutiliser `Audit` sans migration:

- `domain`: domaine scanne.
- `scan_data`: inclure `scan_type: "dns_deep"`.
- `ai_report`: rapport IA DNS, ou objet minimal si l'IA n'est pas appelee.
- `score`: lettre DNS.
- `numeric_score`: score DNS.
- `session_id`: meme session.

Exemple `scan_data`:

```json
{
  "scan_type": "dns_deep",
  "domain": "example.com",
  "ip": "93.184.216.34",
  "dns": {
    "a": [],
    "aaaa": [],
    "cname": [],
    "mx": [],
    "ns": [],
    "txt": [],
    "soa": {},
    "caa": [],
    "dnssec": {
      "enabled": false,
      "ds": [],
      "dnskey": []
    },
    "email_security": {
      "spf": {},
      "dmarc": {},
      "dkim_indicators": []
    },
    "exposure": {
      "zone_transfer": "blocked",
      "wildcard_dns": false,
      "subdomain_signals": []
    }
  },
  "score_details": [
    "+10 pts: SPF strict detecte",
    "-15 pts: DMARC absent"
  ],
  "numeric_score": 75
}
```

Avantage: aucune migration necessaire. Le dashboard Partie 1 ne doit cependant pas pointer vers ces audits, car son template attend des cles HTTP/TLS.

### Option robuste a moyen terme

Ajouter une table dediee `DnsDeepAudit`.

Champs recommandes:

- `id`
- `domain`
- `timestamp`
- `scan_data`
- `ai_report`
- `score`
- `numeric_score`
- `session_id`
- `user_id` nullable pour transition future

Cette option evite les collisions entre schemas `scan_data`, mais necessite une migration ou `db.create_all()`.

## 6. Service DNS profond recommande

Nouveau fichier:

```text
app/services/dns_deep_scanner.py
```

Fonction publique:

```python
def analyze_dns_deep(domain: str) -> dict:
    ...
```

Controles recommandes:

- A, AAAA, CNAME, NS, MX, TXT, SOA, CAA.
- PTR sur les IP A/AAAA publiques.
- DNSSEC: DS et DNSKEY.
- SPF: presence, `-all`, `~all`, `+all`, includes excessifs.
- DMARC: presence de `_dmarc`, politique `p=reject/quarantine/none`, rua/ruf.
- DKIM: ne pas brute-forcer agressivement; tester uniquement des selecteurs connus limites si necessaire.
- Zone transfer AXFR contre les NS, avec timeout strict.
- Wildcard DNS via sous-domaine aleatoire.
- Hygiene MX: redondance, priorites, MX pointant vers IP privee ou domaine inexistant.
- CAA: presence et coherence.
- Delegation: NS incoherents, lame delegation, SOA serial accessible.

Garde-fous reseau:

- Timeouts courts.
- Resolver explicite et configurable.
- Refus IP privees pour toute IP resolue.
- Pas de brute force massif dans le scan synchrone.
- Limiter le nombre de requetes par domaine.
- Retourner des erreurs structurees `PRIVATE_IP`, `NXDOMAIN`, `TIMEOUT`, `DNS_ERROR`.

## 7. Reutilisation du systeme d'authentification

### Decorateur premium

Nouveau fichier:

```text
app/auth/premium.py
```

Pseudo-code:

```python
from functools import wraps
from flask import session, redirect, url_for, flash, abort, request

def is_authenticated_session():
    return bool(session.get("user_api_key"))

def is_premium_session():
    return session.get("is_premium") is True or session.get("plan") == "premium"

def premium_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not is_authenticated_session():
            if request.path.startswith("/premium/dns/api/"):
                abort(401)
            flash("Session expiree. Veuillez vous reconnecter.", "error")
            return redirect(url_for("main.login"))
        if not is_premium_session():
            if request.path.startswith("/premium/dns/api/"):
                abort(403)
            flash("Cette analyse est reservee aux utilisateurs premium.", "error")
            return redirect(url_for("main.index"))
        return view(*args, **kwargs)
    return wrapped
```

### Source du statut premium

Phase 1, minimale:

- Injecter `session['plan'] = 'premium'` apres verification externe.
- Ne jamais accepter `plan=premium` depuis un formulaire client non verifie.

Phase 2, propre:

- Ajouter un modele `User`.
- Ajouter `subscription_tier`, `subscription_status`, `subscription_expires_at`.
- Stocker seulement `user_id` en session.
- Deriver `premium` cote serveur a chaque requete sensible.

Phase 3, SaaS:

- Brancher Stripe, Paddle ou fournisseur interne.
- Ajouter webhooks de mise a jour d'abonnement.
- Ajouter audit log des changements de plan.

## 8. IA et rapport DNS

La Partie 1 appelle `generate_report(scan_res, api_key=session['user_api_key'], model_id=session['user_model_id'])`.

Pour eviter de modifier `app/services/ai.py`, creer:

```text
app/services/dns_ai.py
```

Fonction:

```python
def generate_dns_report(scan_data, api_key, model_id):
    ...
```

Sortie recommandee:

```json
{
  "executive": "Resume dirigeant DNS.",
  "technical": ["Action 1", "Action 2", "Action 3", "Action 4"],
  "risks": {
    "spoofing": 0,
    "mail_fraud": 0,
    "takeover": 0,
    "availability": 0,
    "data_leakage": 0
  }
}
```

Cela permet un radar DNS dedie sans casser le radar HTTP/TLS de la Partie 1.

## 9. Plan d'execution recommande

1. Ajouter `app/auth/premium.py`.
2. Ajouter `app/services/dns_deep_scanner.py`.
3. Ajouter `app/services/dns_scoring.py` seulement si le bareme DNS diverge fortement; sinon reutiliser `calculate_trust_score`.
4. Ajouter `app/services/dns_ai.py`.
5. Ajouter `app/routes_dns.py` avec `dns_bp`.
6. Ajouter `dns_deep_scan.html` et `dns_deep_dashboard.html`.
7. Enregistrer le blueprint via l'option A ou B selon le niveau strict de non-modification des fichiers existants.
8. Ajouter des tests unitaires sur:
   - validation domaine;
   - refus session absente;
   - refus non-premium;
   - refus IP privee;
   - scoring `score_details`;
   - isolation `session_id`.

## 10. Points de vigilance

- Ne pas afficher un audit DNS profond avec `dashboard.html`, car le template Partie 1 attend `ssl`, `headers`, `waf_detected`, `cookies_security` et `tech_stack`.
- Ne pas stocker un statut premium auto-declare dans la session.
- Ne pas lancer de brute force sous-domaines dans une route synchrone sans file de jobs.
- Garder les scans DNS profonds majoritairement passifs.
- Conserver la structure `score_details` pour l'historique et les logs.
- Conserver le consentement legal sur la Partie 2.
- Conserver les timeouts reseau et le filtrage IP privee pour limiter les risques SSRF.

## Decision d'architecture recommandee

Pour une integration propre et compatible avec la Partie 1:

- Creer un blueprint separe `dns_deep`.
- Creer un service `analyze_dns_deep()` qui retourne un JSON autonome avec `scan_type: "dns_deep"`.
- Reutiliser `Audit` en premiere iteration pour eviter une migration.
- Reutiliser `calculate_trust_score()` en respectant les prefixes `+N pts` et `-N pts`.
- Ajouter un decorateur `premium_required` qui s'appuie sur la session Flask actuelle.
- Ajouter des templates dedies qui heritent de `base.html`.
- N'effectuer aucune modification dans `app/routes.py`, `app/services/scanner.py`, `app/templates/index.html` ou `app/templates/dashboard.html`.
