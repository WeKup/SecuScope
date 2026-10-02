# CLAUDE.md — SecuScope

Lu automatiquement à chaque session. Garde-le court : c'est du contexte permanent,
pas une doc. Le détail des tâches est dans `TASKS.md`.

## Projet

Auditeur de sécurité web externe **non intrusif** (reconnaissance passive +
fingerprinting actif léger). Stack : Flask 3 + PostgreSQL 15 + Docker Compose,
rapport LLM via `google-genai`. Repo CV, visé top 20 tech — chaque ligne doit
être défendable en entretien.

## Démarrage d'une session

1. Lire `TASKS.md` et reprendre la tâche en cours (ordre strict, une à la fois).
2. Pour l'UI : déléguer à l'agent `design-lead` et respecter `secuscope-ui-rules.md`.
3. Ne lire que les fichiers nécessaires à la tâche ; ne pas re-scanner tout le repo.

## Invariants — ne jamais casser

- `scan_data` garde ces clés (consommées par `dashboard.html`) : `domain, ip, ssl,
  waf_detected, server, headers, missing_headers, cookies_security, tech_stack,
  score_details, numeric_score`.
- Routes CSRF : `/`, `/scan`, `/dashboard/<int:id>`, `/logout`.
- Scoring : préfixes `+N pts` / `-N pts`, base 50, borné [0,100], grade A–F.
- Erreurs `PRIVATE_IP` et `NXDOMAIN` gérées dans `routes.py`.
- Anti-SSRF (`_is_public_ip`) jamais affaibli (private, loopback, link-local,
  multicast, reserved, unspecified).
- Historique isolé par `session_id`.

## Carte du code (pour viser juste sans tout ouvrir)

- `app/__init__.py` — factory `create_app`, config, CSRF, blueprint.
- `app/routes.py` — routes, validation d'entrée, orchestration du scan.
- `app/services/scanner.py` — moteur réseau (DNS, SSL, HTTP, cascade WAF).
- `app/services/scoring.py` — `calculate_trust_score`.
- `app/services/ai.py` — client google-genai, extraction JSON robuste.
- `app/services/signature.py` — WAF/INFRA/TECH/SECURITY signatures.
- `app/models.py` — modèle `Audit`.
- `app/templates/` — `base.html`, `login.html`, `index.html`, `dashboard.html`,
  `components/vulnerability_chart.html`.

## Conventions

- Python : PEP 8. Exceptions ciblées (pas de `except: pass`).
- Secrets jamais commités ; `.env` ignoré par Git.
- Vocabulaire : « non intrusif » / « fingerprinting actif léger » — jamais
  « passif uniquement » ni « zéro-intrusion » (le code envoie une sonde active).
- UI : dense, enterprise, couleur = sévérité. Pas de cliché IA (néon violet, blobs).
- Commits : aucune ligne d'attribution (pas de Co-Authored-By, pas de "Generated with", pas de lien de session). Message seul.

## Façon de travailler avec moi (Maxime)

- Français, ton informel, explications par analogies plutôt que formalisme.
- Corrections fichier par fichier, pas de re-téléchargement global.
- Une tâche → diff + 2 lignes (quoi/pourquoi) → ma validation → un commit atomique.
- Pas de refactor ni de dépendance non demandés. Prévenir avant de toucher un invariant.
- Sous-agents : lecture seule uniquement, jamais deux écritures en parallèle.

## Hors périmètre

- Partie 2 (DNS premium) : pas avant la fin des tâches 1→6 de `TASKS.md`.
- Pas de migration React/Next sans demande explicite.