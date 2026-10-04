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

- `scan_data` garde ces clés, consommées par `dashboard.html` :
  `domain, ip, ssl, waf_detected, server, headers, missing_headers,
  cookies_security, tech_stack, score_details, numeric_score`.
  Clés **optionnelles** (absentes du kill-switch HTTP et des anciens audits en base,
  toujours les lire avec `.get(..., {})`) : `dns_security`, `tls_deep`.
- Routes disponibles et compatibles CSRF : `/`, `/scan`, `/dashboard/<int:id>`, `/logout`.
- Scoring v2 (`docs/SCORING_V2_SPEC.md`) : 4 catégories /100 (TLS 35, en-têtes 25,
  DNS 25, cookies 15), bonus infra +5 (max +10), caps, grade A/B/C/D/F.
  `scan_data` garde `numeric_score`, `score` et `score_details` (liste dégradée
  `-N pts: ...` en attendant le front) ; détail réel dans `score_breakdown` (optionnelle).
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

## Reprise — état au 03/10/2026

**Fait et commité :**
- DNS profond dans le scanner : SPF, DMARC, DKIM (indice), DNSSEC, CAA, AXFR
  (`app/services/dns_security.py`, `29838cb`). Clé `dns_security`.
- IA nourrie des findings DNS (`ai.py`, `8d6502c`). Structure JSON inchangée.
- TLS approfondi via sslyze : versions, ciphers faibles, forward secrecy
  (`app/services/tls_analysis.py`, `facab29`). Clé `tls_deep`, budget 30 s.
  Heartbleed/ROBOT/CCS : informatifs, aucun point.
- Notes de chantiers (`78c833e`) : recalibrage barème, front DNS/TLS, scan async.

**Pas encore validé :** aucun test bout en bout en conteneur pour DNS/TLS/IA
(modules testés isolément, sslyze hors Flask). À faire en premier.

**TODO rédaction (Maxime, à la main) :** reformuler le périmètre « non intrusif »
du README (§1 capacités, « Périmètre d'exclusion », §2 dernière puce). La phrase
« seule composante active = un GET unique » est fausse (AXFR vers les NS, scan
TLS multi-versions, sonde sslyze). Rédaction sensible, ne pas toucher sans lui.

### Ordre de reprise (chantiers restants)
1. Test bout en bout Docker (`docker compose up --build`) : google.com et
   `zonetransfer.me` (AXFR ouvert attendu).
2. Finaliser `docs/SCORING_V2_SPEC.md` (brouillon du 03/10 : affiner les poids, plafond, bonus infra, classification critique).
3. Appliquer le scoring V2 + fix prompt IA « Géré par Infra » = présent/protégé.
4. Front DNS/TLS (agent `design-lead`) : sections, tri par sévérité, bug couleurs.
5. UI `index.html` / `login.html` + restes tâche 4 (liste « Reste à faire » ci-dessous).
6. Petits points : `.env.example`, `.gitattributes`, Chart.js épinglé, `counts.low`.
7. Durcissement prod (tâche 3), puis scan asynchrone Celery/Redis, puis tests (tâche 6).

## Historique — état au 02/10/2026

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

## Recalibrage du barème (chantier dédié, à faire à froid)
- PLAFOND : les bonus "géants" masquent les malus. Ex. google.com = 100/100 malgré TLS 1.0/1.1 acceptés + cipher faible, car +10 infra Google +20 "Sécurité gérée par Google" poussent au plafond de 100.
- Revoir le poids des bonus infra : être hébergé chez Google/Cloudflare ≠ être bien configuré. Ne pas laisser l'hébergeur écraser les vraies faiblesses de config.
- Aligner la classification critique/moyenne avec la gravité réelle : un AXFR ouvert ou du TLS obsolète devrait pouvoir être "critique" même sans atteindre -50 pts.
- Fix prompt IA : clarifier que le statut "Géré par Infra" d'un en-tête = présent/protégé, PAS absent (sinon l'IA recommande à tort d'ajouter CSP sur google).

## Front — section Sécurité DNS/TLS (à faire)
- Trier les findings par sévérité : NÉGATIFS en premier (critiques → moyens → faibles → positifs). Principe : montrer d'abord ce qui demande une action.
- BUG couleur : tags "Actif" (vert) / "Protégé" (indigo) inversés par rapport à la barre de couverture des en-têtes. Harmoniser : une couleur = un statut partout.
- Ajouter une vraie section "Sécurité DNS" avec tags visibles (SPF, DMARC, DNSSEC, CAA, AXFR : présent/absent/vulnérable).
- Ajouter une section "TLS approfondi" (versions, ciphers faibles, forward secrecy).

## Architecture — scan asynchrone (chantier, justifié par sslyze ~30s)
- Migrer le scan vers Celery + Redis : lancer → job_id → polling du statut → dashboard.
- Refaire le loader pour afficher la VRAIE progression (remplace les faux timings GSAP actuels + "PROBES 6/6").

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

### 4. Cohérence passif / actif léger — PARTIELLE
Fait : badge `index.html` (« Scanner externe non intrusif »), « autorisation écrite »
dans le consentement. Footer de `base.html` : « Reconnaissance passive & fingerprinting
actif léger » encore ambigu, à reformuler. Reste : `PROBES: 6/6`, faux timings du
loader (→ chantier async), `<title>`, README (TODO Maxime ci-dessus).

Énoncé d'origine : le code envoie une sonde active (`/?id=1' OR '1'='1'`). Remplacer PARTOUT
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

## Hors périmètre
- Ne pas migrer vers React/Next sans demande explicite (cf. `secuscope-ui-rules.md`).