# Spec — Scoring SecuScope v2 (catégories + caps)

> Finalisée le 04/10/2026. Prête pour implémentation.
> Modèle inspiré de SSL Labs : notation par catégorie + plafonnement par faille grave.

---

## 1. Le problème du scoring v1

Système additif : base 50, on empile des `+N/-N pts`, borné à 100. Défauts :
- **Effet plafond** : les bonus dépassent 100, les malus sont absorbés.
  google.com = 100/100 malgré TLS 1.0/1.1 + cipher faible.
- **Dimensions interchangeables** : un bonus infra compense une faille TLS.
- **« Géré par Infra » trompeur** : le scanner requalifie les en-têtes ABSENTS
  en « protégés » dès qu'un CDN est détecté → gonfle le score à tort.

---

## 2. Principes de la v2

1. **Catégories étanches** : chaque dimension notée /100 séparément, puis moyenne
   pondérée. Une faille dans une catégorie ne peut pas être compensée par une autre.
2. **Part de 100, on déduit** : chaque catégorie part d'une config parfaite, on
   déduit pour chaque problème (absence de protection OU faiblesse active).
   Plancher à 0. Gère les deux cas de la même façon.
3. **Caps** : une faille grave plafonne le score final, quels que soient les
   autres mérites (analogie contrôle technique : freins morts = recalé).
4. **On observe, on ne suppose jamais** : un en-tête compte comme présent
   seulement s'il est réellement dans la réponse HTTP. Pas de « Géré par Infra ».

---

## 3. Notation par catégorie (chacune part de 100, plancher 0)

### TLS/SSL
| Problème | Déduction |
|---|---|
| Certificat invalide / expiré / mismatch | −40 (+ cap D) |
| SSLv2 ou SSLv3 accepté | −40 (+ cap C) |
| TLS 1.0 ou 1.1 accepté | −20 |
| Cipher suite **cassée** (RC4, DES, EXPORT, NULL, MD5, anonyme) | −25 |
| Cipher suite **legacy** (3DES) | −15 |
| Pas de forward secrecy | −20 |

> Distinction des ciphers : RC4/DES/EXPORT/NULL sont réellement cassés (attaque
> pratique) → −25. 3DES est seulement vieux (Sweet32, difficile à exploiter) →
> −15. SSL Labs fait la même distinction.
| TLS 1.3 non supporté | −10 |

### En-têtes HTTP (déductions = 100 au total → site sans rien = 0)
| En-tête absent | Déduction |
|---|---|
| CSP (Content-Security-Policy) | −25 |
| HSTS (Strict-Transport-Security) | −25 |
| X-Frame-Options (anti-clickjacking) | −20 |
| X-Content-Type-Options (anti-MIME) | −15 |
| Referrer-Policy | −8 |
| Permissions-Policy | −7 |

> **Présence = observée dans la réponse HTTP uniquement.** Peu importe qui pose
> l'en-tête (serveur ou CDN) : s'il est dans la réponse, il compte ; s'il est
> absent, il est absent, même derrière un CDN. On SUPPRIME la requalification
> « Géré par Infra » du scanner. (HSTS vérifié aussi sur `www.` = observation
> légitime, on garde.)

### DNS
| Problème | Déduction |
|---|---|
| SPF absent ou `+all` | −25 |
| DMARC absent | −25 (`p=none` : −12) |
| AXFR (transfert de zone) ouvert | −30 (+ cap C) |
| DNSSEC absent | −12 |
| CAA absent | −8 |
| DKIM | informatif, 0 (6 sélecteurs testés, non exhaustif) |

### Cookies
- **Aucun cookie → 100** (rien à risque, neutre).
- Sinon : moyenne sur les cookies de **(Secure 0,4 + HttpOnly 0,4 + SameSite 0,2)**, × 100.
- SameSite : petit poids car les navigateurs appliquent `Lax` par défaut depuis 2020.

---

## 4. Poids des catégories

| Catégorie | Poids |
|---|---|
| TLS/SSL | 35 % |
| En-têtes HTTP | 25 % |
| DNS | 25 % |
| Cookies | 15 % |

---

## 5. Bonus infrastructure

WAF/CDN détecté (Cloudflare, Akamai, Google Edge...) = **+5** (plafonné à **+10**
si plusieurs couches). Justification : un WAF filtre réellement des attaques
(DoS/DDoS, patterns connus). Appliqué AVANT les caps → ne peut jamais racheter
une faille grave ni transformer un site mal configuré en bon score.

---

## 6. Caps (plafonds déclenchés par faille grave)

| Faille | Score maximum autorisé |
|---|---|
| HTTP en clair / HTTPS non forcé | **20** (F) — kill-switch |
| Certificat TLS invalide / expiré / mismatch | **59** (D) |
| SSLv2 ou SSLv3 accepté | **79** (C) |
| AXFR ouvert | **79** (C) |

Le cap prend le **minimum** entre le score calculé et le plafond de la pire
faille déclenchée.

---

## 7. Formule d'agrégation

```
1. Pour chaque catégorie : note_cat = 100 − Σ déductions   (plancher 0)
2. score = Σ (note_cat × poids_cat)                         # 0–100
3. score = score + bonus_infra                              # +5, max +10
4. score = min(score, 100)
5. score = min(score, plafond le plus bas déclenché par un cap)
6. grade : A ≥ 90 · B 80–89 · C 60–79 · D 40–59 · F < 40
```

---

## 8. Effet attendu (validation)

- **google.com** (TLS 1.0/1.1 + 3DES, 3 en-têtes réellement absents) :
  TLS ≈ 55/100, En-têtes pénalisés (plus de « Géré par Infra » qui pardonne)
  → descend à un **B honnête** au lieu d'un A artificiel.
- **Petit site bien configuré, sans CDN** : peut atteindre **A** (on note la
  config, pas l'hébergeur).
- **zonetransfer.me** (AXFR ouvert) : **cappé à C** quoi qu'il arrive.

---

## 9. Changements de code impliqués

1. **Réécrire `scoring.py`** selon cette structure (catégories + poids + caps).
   Le format `+N/-N pts` disparaît au profit de notes par catégorie.
2. **`scanner.py`** : SUPPRIMER la requalification des en-têtes manquants en
   « Géré par Infra » quand une infra premium est détectée. Garder l'observation
   brute de `get_http_info`.
3. **`scanner.py` / `_audit_cookies`** : ajouter l'extraction de l'attribut
   **SameSite** (petit poids dans la note cookies).
4. **`tls_analysis.py`** : exposer proprement les éléments nécessaires au scoring
   TLS (versions acceptées, ciphers faibles, PFS).
5. **`ai.py`** : « Géré par Infra » n'existe plus → l'IA voit les en-têtes
   réellement absents comme absents (elle a raison de recommander de les ajouter).
6. **Dashboard** (chantier front séparé) : afficher la note PAR catégorie, et
   indiquer quand un cap s'est appliqué (« Note plafonnée à C : AXFR ouvert »).
7. **Invariant CLAUDE.md** : la règle scoring `+N/-N pts` est remplacée par ce
   modèle. Mettre à jour l'invariant.

---

## 10. TODO ultérieurs (hors refonte)
- Classification critique/moyenne/faible à aligner sur les caps (un cap = critique).
- SameSite : déjà intégré ici (petit poids).
