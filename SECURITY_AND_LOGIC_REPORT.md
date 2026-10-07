# Rapport securite et logique - Partie 1

## Synthese

La Partie 1 ne contient pas d'injection OS directe: aucun appel shell, `subprocess`, `os.system` ou composition de commande n'a ete trouve dans le flux de scan. Les risques principaux sont ailleurs: SSRF par resolution DNS incomplete, stockage de secrets dans la session Flask client-side, validation de session minimale, logique reseau redondante, scoring IA calcule trop tard, parsing fragile de reponse IA et audit cookie approximatif.

## Failles et corrections prioritaires

### 1. SSRF et DNS rebinding partiellement couverts

Constat:

- `get_dns_info()` ne resolvait que le premier enregistrement A.
- `is_safe_domain()` ne refusait que `is_private`, pas loopback, link-local, multicast, reserved, unspecified.
- Les connexions HTTP/TLS re-resolvent le domaine apres le premier controle.

Impact:

- Un domaine avec plusieurs A/AAAA, ou une resolution changeante, pouvait contourner le controle initial.
- Les cibles internes ou speciales pouvaient etre sous-filtrees.

Correction appliquee:

- Resolution centralisee avec resolver timeout.
- Collecte de tous les A et AAAA.
- Refus si une IP resolue est non publique.
- Conservation de `ip` pour compatibilite dashboard.
- Recontrole avant connexions TCP/HTTPS.

Risque residuel:

- Pour supprimer totalement le DNS rebinding, il faudrait pinner l'IP au niveau transport tout en conservant SNI/Host, ce qui demande une couche HTTP adaptee.

### 2. Secrets dans session Flask

Constat:

- `user_api_key` est place dans `session`.
- Flask stocke par defaut la session dans un cookie signe cote client.

Impact:

- Le secret n'est pas modifiable sans `SECRET_KEY`, mais il peut etre lisible cote client selon le serializer Flask.

Correction appliquee:

- Validation de taille et presence de la cle.
- Whitelist stricte des modeles Gemini acceptes.
- Durcissement cookies: `HttpOnly`, `SameSite=Lax`, `Secure` configurable.
- Duree de session limitee.

Risque residuel:

- La vraie correction structurelle est une session serveur ou un coffre applicatif pour l'API key. Cela doit etre traite avant une offre premium multi-utilisateur.

### 3. Prompt IA incoherent

Constat:

- `generate_report()` etait appele avant l'ajout de `numeric_score`.
- Le prompt recevait donc souvent `N/A`.

Impact:

- Rapport IA moins coherent que le score affiche.

Correction appliquee:

- Calcul du score avant generation IA.
- Injection de `numeric_score` avant appel IA.

### 4. Modele IA non valide

Constat:

- `model_id` venait directement du formulaire.

Impact:

- Erreurs API, couts imprevus ou usage de modeles non prevus par le produit.

Correction appliquee:

- Whitelist cote serveur des modeles supportes.
- Valeur par defaut sure.

### 5. Parsing IA fragile

Constat:

- Le code supprimait simplement les fences Markdown puis faisait `json.loads`.

Impact:

- Une reponse contenant du texte autour du JSON cassait tout le rapport.

Correction appliquee:

- Extraction robuste du premier objet JSON.
- Normalisation du schema de retour.
- Fallback stable en cas d'erreur.

### 6. Audit cookie approximatif

Constat:

- La presence de `secure` dans l'ensemble du header `Set-Cookie` pouvait marquer tous les cookies comme securises.

Impact:

- Faux positifs sur la securite cookie.

Correction appliquee:

- Analyse par cookie quand les headers multiples sont accessibles.
- Fallback conservateur si l'association exacte est impossible.
- Signalement separe `Secure` et `HttpOnly`.

### 7. Requetes reseau lentes ou redondantes

Constat:

- Plusieurs resolutions DNS implicites et timeouts disperses.
- `requests.Session` etait appele avec `impersonate` a la creation, ce qui n'est pas necessaire.

Correction appliquee:

- Timeouts DNS explicites.
- Constantes de timeout separees.
- Reutilisation de headers.
- Suppression des imports inutilises.
- Analyse WAF preservee mais encapsulee pour echouer vite sans casser le scan.

### 8. Gestion d'erreurs trop silencieuse

Constat:

- De nombreux `except: pass` cachaient le contexte.

Impact:

- Difficile de diagnostiquer les erreurs reseau.

Correction appliquee:

- Exceptions ciblees sur DNS, SSL, socket et HTTP.
- Details fonctionnels conserves dans `score_details` quand utile.

## Verification attendue

Les invariants suivants doivent rester vrais:

- Les routes `/`, `/scan`, `/dashboard/<id>` et `/logout` restent disponibles.
- Le formulaire CSRF reste compatible.
- `scan_data` conserve les cles consommees par `dashboard.html`:
  - `domain`
  - `ip`
  - `ssl`
  - `waf_detected`
  - `server`
  - `headers`
  - `missing_headers`
  - `cookies_security`
  - `tech_stack`
  - `score_details`
  - `numeric_score`
- Les erreurs `PRIVATE_IP` et `NXDOMAIN` restent gerees par `routes.py`.
- Le scoring reste base sur les prefixes `+N pts` et `-N pts`.
