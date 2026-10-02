# SecuScope — Feuille de route Claude Code

> Lis ce fichier au début de chaque session. Il remplace l'ancien `codex.md`.

## Contexte

SecuScope est un auditeur de sécurité web externe **non intrusif** (reconnaissance
passive + fingerprinting actif léger). Stack : Flask 3 + PostgreSQL 15 + Docker
Compose, rapport LLM via `google-genai`.

**Avant de coder quoi que ce soit**, lis dans cet ordre :
`README.md`, `app/__init__.py`, `app/routes.py`, `app/services/scanner.py`,
`app/services/scoring.py`, `app/services/ai.py`, `app/models.py`,
`app/services/signature.py`, puis les templates de `app/templates/`.

## Invariants — NE JAMAIS casser (vérifier après CHAQUE tâche)

- `scan_data` garde exactement ces clés, consommées par `dashboard.html` :
  `domain, ip, ssl, waf_detected, server, headers, missing_headers,
  cookies_security, tech_stack, score_details, numeric_score`.
- Routes disponibles et compatibles CSRF : `/`, `/scan`, `/dashboard/<int:id>`, `/logout`.
- Scoring basé sur les préfixes `+N pts` / `-N pts` (regex `^([+-]\d+)\s*pts`).
  Base 50, borné [0,100], grade A/B/C/D/F.
- Erreurs `PRIVATE_IP` et `NXDOMAIN` gérées par `routes.py`.
- Anti-SSRF (`_is_public_ip`) jamais affaibli : refuse private, loopback,
  link-local, multicast, reserved, unspecified.
- Isolation de l'historique par `session_id` sur `/dashboard`.

## Règles de travail

- **Une tâche à la fois**, dans l'ordre ci-dessous. Pas de travail en parallèle
  sur les mêmes fichiers.
- Après chaque tâche : montrer le diff, expliquer en 2 lignes quoi + pourquoi,
  attendre ma validation, puis **un seul commit atomique** par tâche.
- Pas de refactor non demandé. Pas de nouvelle dépendance sans me prévenir.
- Si une tâche touche un invariant ci-dessus, me prévenir AVANT.
- Sous-agents autorisés uniquement en **lecture seule** (recherche, audit).
  Jamais deux agents qui écrivent en même temps.
- Pour l'UI : déléguer à l'agent `design-lead` (voir `.claude/agents/design-lead.md`)
  et respecter `secuscope-ui-rules.md`.

## Reprise — état au 02/10/2026

**Fait :** tâche 1 (driver DB, vérifié en conteneur), tâche 2 (`normalize_domain`),
fix XSS + injection JS du dashboard (`a08688b`), design system indigo dans
`base.html` + refonte du dashboard, règles UI et `design-lead.md` alignés,
README à jour (`007b165`).

**Reste à faire, dans cet ordre (avant de reprendre la tâche 3) :**

1. **UI — `index.html`** au niveau du dashboard : tokens/composants de `base.html`,
   retirer l'import Motion (→ `.reveal` CSS), loader GSAP conservé (seul endroit
   autorisé) avec `prefers-reduced-motion`, retirer les faux timings `+420ms`
   et le `PROBES 6/6` statique, focus visible + labels associés. Graisses Inter
   300/800 plus chargées : remplacer `font-light` / `font-extrabold`.
2. **UI — `login.html`** idem : design system, retirer l'import Motion, labels
   `for`/`id`, note « clé en session uniquement » reliée par `aria-describedby`.
3. **Nettoyage design system** : retirer l'override temporaire `slate.950` de
   `base.html`, chercher les résidus `slate-[3-8][05]0` et les hex en dur.
4. **`.env.example`** : ajouter `SESSION_COOKIE_SECURE=false` (lue par
   `app/__init__.py`, documentée dans le README §5, absente du gabarit).
5. **`.gitattributes`** : normaliser les fins de ligne (`* text=auto eol=lf`,
   binaires exclus) — Git avertit « LF will be replaced by CRLF » à chaque commit.
6. **Points en suspens à trancher avec Maxime :**
   - Faux finding : `getVulnerabilityCounts` (dashboard) force `counts.low = 1`
     quand il n'y a aucun finding → le hero affiche « 1 faible » sur un site
     parfait. Logique d'affichage, ne pas corriger sans accord.
   - Textes des grades C et D du barème (dialog `#scoreModal`) rédigés par
     Claude : à relire.
   - Chart.js chargé sans version épinglée (`cdn.jsdelivr.net/npm/chart.js`) :
     épingler une version exacte (même problème que Motion `@latest`).

## Tâches, par priorité

### 1. Fix driver DB (BLOQUANT)
Dans `app/__init__.py`, forcer `postgresql+psycopg2://` à partir de `DATABASE_URL`.
Sans ça le conteneur crashe : `ModuleNotFoundError: No module named 'psycopg'`.
Vérifier ensuite `docker compose up --build -d` + un scan de test.

### 2. Normalisation de l'URL saisie
Accepter `http(s)://`, chemins, ports, casse, `user:pass@` — n'extraire que le
host avant `validators.domain`. Fonction `normalize_domain()` dans `routes.py`,
appelée à la place du `.strip()` actuel. Ne pas stripper `www.`.

### 3. Durcissement production
- `run.py` : `debug` piloté par `FLASK_DEBUG` (défaut False).
- Servir via gunicorn (déjà dans `requirements.txt`) : adapter `Dockerfile`/compose.
- Retirer la clé `version:` obsolète de `docker-compose.yml`.
- Ajouter un `USER` non-root au `Dockerfile`.
- Ajouter un `healthcheck` sur `db` + `depends_on: condition: service_healthy`.

### 4. Cohérence passif / actif léger
Le code envoie une sonde active (`/?id=1' OR '1'='1'`). Remplacer PARTOUT
« passif uniquement » / « zéro-intrusion » par « non intrusif » /
« fingerprinting actif léger » : README + `base.html` (footer, `<title>`),
`index.html` (badge, consentement, loader, barre du bas), et le compteur
`PROBES_ACTIVE: 6/6`. Renforcer le texte de consentement : « autorisation **écrite** ».

### 5. Mettre le README à jour (après chaque tâche terminée)
- Cocher la roadmap §8.3 au fil de l'eau.
- Remonter en capacités réelles (hors §7) : whitelist des modèles Gemini,
  `MAX_API_KEY_LENGTH`, durcissement des cookies de session (HttpOnly,
  SameSite, Secure, durée 4h).

### 6. Tests
Suite `tests/` (pytest) : normalisation d'URL, refus IP privée, refus sans
consentement, parsing `score_details`, isolation par `session_id`,
extraction JSON robuste de `ai.py`.

### 7. (Plus tard) Partie 2 — Scan DNS profond premium
Suivre le plan d'intégration existant. Blueprint séparé `dns_deep`, décorateur
`premium_required`, réutiliser `Audit` + `calculate_trust_score`. NE PAS toucher
`routes.py`, `scanner.py`, `index.html`, `dashboard.html`. Hors périmètre tant
que 1→6 ne sont pas finis.

## Hors périmètre
- Ne pas démarrer la Partie 2 avant la fin des tâches 1→6.
- Ne pas migrer vers React/Next sans demande explicite (cf. `secuscope-ui-rules.md`).