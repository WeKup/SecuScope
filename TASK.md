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

## Reprise — état au 04/10/2026

**Fait et commité le 04/10 :**
- Scoring v2 (`420c765`) : 4 catégories /100 pondérées (TLS 35, en-têtes 25, DNS 25,
  cookies 15), bonus infra +5 (max +10), caps (HTTP clair 20, certificat 59, SSLv2/3 79,
  AXFR 79), ciphers cassés −25 / 3DES legacy −15. « Géré par Infra » supprimé du scanner,
  `SameSite` extrait des cookies, prompt IA adapté, invariant scoring mis à jour.
  Clés ajoutées : `score_breakdown` (détail par catégorie + cap), `critical_failure`.
- Dashboard v2 (`fde3e1c`) : notes par catégorie, bandeau de cap, sections « DNS &
  messagerie » et « TLS / SSL » (macro `components/check_row.html`), tri par sévérité,
  bug couleurs Actif/Protégé corrigé, compteurs critique/moyen/faible dérivés de
  `score_breakdown`, faux « 1 faible » corrigé, modale du barème réécrite, repli
  « Barème v1 » pour les anciens audits.
- Test bout en bout Docker : google.com (72, C) et zonetransfer.me (79, C, cappé AXFR),
  mozilla.org (98, A), ancien audit simulé (rendu sans erreur).

**Fait et commité le 03/10 :**
- DNS profond (`29838cb`), IA nourrie des findings DNS (`8d6502c`), TLS approfondi
  sslyze (`facab29`, budget 30 s, Heartbleed/ROBOT/CCS informatifs), notes de chantiers
  (`78c833e`), spec scoring (`7494fe4`).

**Pas encore validé :** le rapport IA n'a jamais tourné bout en bout avec une vraie
clé Gemini depuis l'ajout DNS/TLS/scoring v2 (les tests Docker ont utilisé une clé
factice → rapport en erreur). À faire avec une vraie clé.

**Non commité (état du dépôt) :** `docs/SCORING_V2_SPEC.md` (version à jour, distinction
cipher cassé/legacy) et `app/templates/index.html` ont des modifications locales.

**TODO rédaction (Maxime, à la main) :** reformuler le périmètre « non intrusif »
du README (§1 capacités, « Périmètre d'exclusion », §2 dernière puce). La phrase
« seule composante active = un GET unique » est fausse (AXFR vers les NS, scan
TLS multi-versions, sonde sslyze). Rédaction sensible, ne pas toucher sans lui.

### TODO issus du scoring v2 / dashboard v2 (découverts le 04/10)
- **Cap « cipher cassé »** (`scoring.py`) : RC4, DES, EXPORT, NULL, MD5, anonyme → plafond
  de la note finale (cohérent SSL Labs). Aujourd'hui seulement −25 dans la catégorie TLS,
  donc un site avec RC4 peut encore viser B. Valeur du plafond à trancher avec Maxime,
  à ajouter à la spec (§6) puis au dashboard (table des plafonds de la modale).
- **Kill-switch HTTP** (`scanner.py` / `scoring.py`) : `dns_security` et `tls_deep`
  absents du kill-switch, donc DNS, TLS et cookies sont notés 100 à tort. La note finale
  reste correcte (cap 20) mais le détail par catégorie est faux. Soit le scanner
  renvoie les données DNS/TLS même en kill-switch, soit le scoring marque la catégorie
  « non évaluée » (le dashboard affiche déjà « note par défaut, non significative »).
- **Modale du barème** : les plafonds (20/59/79/79) sont recopiés en dur dans
  `dashboard.html`. À lire du backend (constantes de `scoring.py` exposées dans
  `score_breakdown`) pour qu'un changement de barème ne désynchronise pas la modale.
- Compteurs du hero : un cipher cassé est affiché critique dans la table TLS mais compté
  « moyen » (déduction 25, pas de cap) ; Heartbleed/CCS/ROBOT positifs affichés critiques
  mais non comptés. À aligner une fois le cap « cipher cassé » décidé.
- Plafond silencieux : `score_breakdown.cap` n'est rempli que si le plafond est inférieur
  au score calculé (un AXFR ouvert sur un site à 70 ne produit pas de bandeau). Voulu ;
  la ligne AXFR reste en évidence dans la section DNS.

### Ordre de reprise (chantiers restants)
1. Valider le rapport IA bout en bout avec une vraie clé Gemini.
2. Cap « cipher cassé » + fix kill-switch (voir TODO ci-dessus), puis modale lue du backend.
3. UI `index.html` / `login.html` + restes tâche 4 (liste « Reste à faire » ci-dessous).
4. Petits points : `.env.example`, `.gitattributes`, Chart.js épinglé, textes des grades
   C et D de la modale à relire (réécrits par `design-lead` le 04/10).
5. Durcissement prod (tâche 3), puis scan asynchrone Celery/Redis, puis tests (tâche 6).

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
   - ~~Faux finding `counts.low = 1`~~ : corrigé le 04/10 (`fde3e1c`).
   - Textes des grades du barème (dialog `#scoreModal`) réécrits le 04/10 par
     `design-lead` pour le scoring v2 : à relire.
   - Chart.js chargé sans version épinglée (`cdn.jsdelivr.net/npm/chart.js`) :
     épingler une version exacte (même problème que Motion `@latest`).

## Recalibrage du barème — FAIT le 04/10 (`420c765`)
Plafond des bonus infra (+5, max +10, avant les caps), hébergeur ≠ bien configuré,
classification critique alignée sur les caps (compteurs du dashboard, `fde3e1c`),
prompt IA « Géré par Infra » : la notion est supprimée, un en-tête absent est absent.
Reste : cap « cipher cassé » (voir TODO en haut).

## Front — section Sécurité DNS/TLS — FAIT le 04/10 (`fde3e1c`)
Tri par sévérité, bug couleurs Actif/Protégé, section « DNS & messagerie »,
section « TLS / SSL » approfondie.

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