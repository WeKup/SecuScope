# Spec — Refonte du scoring SecuScope (v2 : catégories + caps)

> Décision d'architecture prise le 03/10/2026. Poids à affiner demain avant implémentation.
> Inspiré du modèle SSL Labs (notation par catégorie + plafonnement par faille grave).

---

## Le problème du scoring v1 (actuel)

Système purement **additif** : base 50, on empile des `+N/-N pts`, borné à 100.
Deux défauts constatés en test :
1. **Effet plafond** : les bonus dépassent 100, donc les malus sont absorbés.
   → google.com = 100/100 malgré TLS 1.0/1.1 acceptés + cipher faible.
2. **Dimensions interchangeables** : un bonus infra compense une faille TLS, ce
   qui n'a aucun sens — être hébergé chez Google ne répare pas un cipher faible.

**Racine** : un système additif traite toutes les dimensions comme fongibles.
Or en sécurité, une chaîne vaut son maillon le plus faible.

---

## Les 2 principes de la v2

### 1. Notation par catégories étanches
Chaque dimension est notée séparément (sur 100), puis agrégée par moyenne
pondérée. Une faille dans une catégorie ne peut PAS être compensée par une
autre.

### 2. Caps (plafonnement par faille grave)
Certaines failles imposent un plafond au score final, quels que soient les
autres mérites. Analogie du contrôle technique : freins morts = recalé, peu
importe la carrosserie. SSL Labs fait ça (SSLv3 → note max C).

---

## Architecture proposée

### Catégories et poids (PROPOSÉS — à valider demain)

| Catégorie | Poids | Contenu |
|---|---|---|
| **TLS/SSL** | 35 % | certificat valide, versions acceptées, ciphers, forward secrecy |
| **En-têtes HTTP** | 25 % | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer, Permissions |
| **DNS** | 25 % | SPF, DMARC, DNSSEC, CAA, AXFR |
| **Cookies** | 15 % | Secure, HttpOnly par cookie |
| **Total** | 100 % | |

Chaque catégorie est notée 0–100 selon ses propres contrôles.

### L'infrastructure = bonus plafonné, PAS une catégorie
Être derrière un WAF/CDN (Cloudflare, Akamai...) donne un **petit bonus final**
(ex. +5 à +10 points max), mais **ne peut jamais** transformer un mauvais score
en bon. L'hébergeur n'est pas la configuration.

### Caps (plafonds déclenchés par faille grave)

| Faille | Plafond imposé |
|---|---|
| HTTP en clair / HTTPS non forcé | **F** (score ≤ 20) — kill-switch actuel conservé |
| Certificat TLS invalide / expiré / mismatch | **D** (≤ 50) |
| SSLv2 ou SSLv3 accepté | **C** (≤ 70) |
| Transfert de zone AXFR ouvert | **C** (≤ 70) |

### Formule d'agrégation
```
1. Pour chaque catégorie : note_cat = contrôles de la catégorie (0–100)
2. score = Σ (note_cat × poids_cat)
3. score = score + bonus_infra (plafonné, ex. +10 max)
4. score = min(score, 100)
5. Appliquer les caps : score = min(score, plafond le plus bas déclenché)
6. Convertir en grade A–F
```
Le cap prend le **minimum** entre le score calculé et le plafond de la pire
faille. Une faille grave tire le score vers le bas, elle ne se noie pas dans
la moyenne.

### Grades (seuils actuels conservés)
A ≥ 90 · B 80–89 · C 60–79 · D 40–59 · F < 40

---

## Effet attendu (validation de la direction)

- **google.com** (TLS 1.0/1.1 + cipher faible) : catégorie TLS pénalisée →
  descend à un **B honnête** au lieu d'un A artificiel. Juste.
- **Petit site bien configuré, sans gros CDN** : peut atteindre **A**, car on
  note la config, pas l'hébergeur. Juste.
- **zonetransfer.me** (AXFR ouvert) : cappé à **C** quoi qu'il arrive, même
  avec un bon TLS. Juste.

---

## À faire demain

1. **Affiner les poids** des catégories (35/25/25/15 à discuter).
2. **Définir la note interne de chaque catégorie** : comment TLS passe de ses
   contrôles (versions, ciphers, PFS) à une note /100, idem pour les autres.
3. **Finaliser la liste des caps** et leurs plafonds.
4. **Réécrire `scoring.py`** selon cette structure.
5. **Adapter le dashboard** : afficher la note PAR catégorie (plus lisible et
   plus pro qu'une liste de `+/- pts`), et indiquer quand un cap s'est appliqué
   (« Note plafonnée à C : transfert de zone AXFR ouvert »).
6. **Fix prompt IA** : « Géré par Infra » = en-tête présent/protégé, pas absent.

---

## À retenir pour un entretien

« J'ai refondu le scoring en notation par catégories pondérées avec
plafonnement par faille grave, inspiré de SSL Labs : une faille critique
plafonne la note au lieu d'être noyée dans une moyenne, et la qualité de
l'hébergeur ne peut pas masquer une mauvaise configuration. »
