"""Scoring v2 : 4 catégories notées /100, moyenne pondérée, bonus infra, caps.

Voir docs/SCORING_V2_SPEC.md. Chaque catégorie part de 100 et déduit pour
chaque problème observé (plancher 0). Un contrôle non vérifié (erreur,
timeout, clé absente) ne déduit rien : on ne punit pas ce qu'on n'a pas vu.
"""
import re

from app.services.signature import NON_PROTECTIVE_LAYERS

WEIGHTS = {"tls": 35, "headers": 25, "dns": 25, "cookies": 15}
CATEGORY_LABELS = {"tls": "TLS/SSL", "headers": "En-têtes HTTP", "dns": "DNS", "cookies": "Cookies"}

INFRA_BONUS_PER_LAYER = 5
INFRA_BONUS_MAX = 10

CAP_HTTP_CLEAR = 20
CAP_BAD_CERT = 59
CAP_LEGACY_SSL = 79
CAP_BROKEN_CIPHER = 79
CAP_AXFR = 79

# Clés = noms d'affichage de SECURITY_HEADERS (signature.py). Total = 100.
HEADER_DEDUCTIONS = {
    "CSP": 25,
    "HSTS": 25,
    "Anti-Clickjacking": 20,
    "Anti-Mime": 15,
    "Referrer": 8,
    "Permissions": 7,
}

# Vieux mais pas cassé en pratique (Sweet32) ; tout autre cipher faible est cassé.
LEGACY_CIPHERS = {"3DES"}

COOKIE_WEIGHTS = {"secure": 0.4, "httponly": 0.4, "samesite": 0.2}


# Cause d'un arrêt anticipé du scan (clé `failure_kind` de scan_data). Par défaut (anciens audits) : HTTP en clair.
FAILURE_LABELS = {
    "http_clear": "HTTP en clair / HTTPS non forcé",
    "tls_handshake": "Handshake TLS échoué (protocole/cipher obsolète ou incompatible)",
    "cert_invalid": "Certificat TLS invalide",
}


def failure_label(scan):
    return FAILURE_LABELS.get(scan.get("failure_kind"), FAILURE_LABELS["http_clear"])



# Déductions qui correspondent à une faille plafonnante = sévérité « critique ».
CAPPING_LABELS = {
    "Certificat invalide, expiré ou ne correspond pas au domaine",
    "SSLv2/SSLv3 accepté",
    "Transfert de zone AXFR ouvert",
}
CAPPING_LABEL_PREFIXES = ("Cipher suite cassée",)
MEDIUM_MIN_POINTS = 12  # déduction ≥ 12 pts = moyenne, en dessous = faible


def deduction_severity(label, points):
    """Sévérité SecuScope d'une déduction : 'critical' (plafonnante), 'medium' ou 'low'.

    Même règle que les compteurs du dashboard (templates/dashboard.html)."""
    if label in CAPPING_LABELS or str(label).startswith(CAPPING_LABEL_PREFIXES):
        return "critical"
    return "medium" if points >= MEDIUM_MIN_POINTS else "low"


def _category(key, deductions, evaluated=True):
    """deductions : liste de (points, libellé). Retourne le bloc d'une catégorie.

    `evaluated=False` : la catégorie n'a pas pu être mesurée (scan interrompu, contrôle absent).
    Elle n'a alors ni note ni poids dans la moyenne : jamais un faux 100.
    """
    block = {"label": CATEGORY_LABELS[key], "weight": WEIGHTS[key], "evaluated": evaluated}
    if not evaluated:
        return {**block, "score": None, "deductions": []}
    total = sum(points for points, _label in deductions)
    return {
        **block,
        "score": max(0, round(100 - total)),
        "deductions": [{"points": round(p), "label": label} for p, label in deductions],
    }


def _score_tls(scan, caps):
    if scan.get("critical_failure"):  # connexion HTTPS jamais établie : rien n'a été mesuré
        return _category("tls", [], evaluated=False)
    deductions = []
    ssl_info = scan.get("ssl", {})
    # Ni verdict sur le certificat ni analyse approfondie aboutie : rien n'a été mesuré, pas de faux 100.
    cert_known = ssl_info.get("valid") or ssl_info.get("error_type") == "ssl_mismatch"
    if not cert_known and (scan.get("tls_deep") or {}).get("status") != "ok":
        return _category("tls", [], evaluated=False)
    # Seule une vraie erreur de certificat déduit : un handshake ou un test qui échoue (timeout, cipher
    # incompatible) n'est pas la preuve d'un certificat invalide.
    if not ssl_info.get("valid") and ssl_info.get("error_type") == "ssl_mismatch":
        deductions.append((40, "Certificat invalide, expiré ou ne correspond pas au domaine"))
        caps.append((CAP_BAD_CERT, "certificat TLS invalide"))

    deep = scan.get("tls_deep") or {}
    if deep.get("status") != "ok":
        return _category("tls", deductions)

    protocols = deep.get("protocols") or {}
    if protocols.get("SSLv2") or protocols.get("SSLv3"):
        deductions.append((40, "SSLv2/SSLv3 accepté"))
        caps.append((CAP_LEGACY_SSL, "SSLv2/SSLv3 accepté"))
    if protocols.get("TLSv1.0") or protocols.get("TLSv1.1"):
        deductions.append((20, "TLS 1.0/1.1 accepté"))
    # Une seule déduction cipher : la pire l'emporte (cassé −25, sinon 3DES legacy −15).
    weak = deep.get("weak_ciphers") or []
    broken = [c for c in weak if c not in LEGACY_CIPHERS]
    if broken:
        deductions.append((25, "Cipher suite cassée (" + ", ".join(broken) + ")"))
        caps.append((CAP_BROKEN_CIPHER, "cipher suite cassée acceptée (" + ", ".join(broken) + ")"))
    elif weak:
        deductions.append((15, "Cipher suite legacy (" + ", ".join(weak) + ")"))
    if deep.get("forward_secrecy") is False:
        deductions.append((20, "Forward secrecy absente"))
    if protocols.get("TLSv1.3") is False:
        deductions.append((10, "TLS 1.3 non supporté"))
    return _category("tls", deductions)


def _score_headers(scan):
    """Présent = observé dans la réponse HTTP, quel que soit qui pose l'en-tête."""
    statuses = scan.get("headers") or {}
    # Seuls « Présent » et « Manquant » sont des observations ; « Non vérifiable » ne déduit rien.
    observed = {n: str(v) for n, v in statuses.items() if "Présent" in str(v) or "Manquant" in str(v)}
    if not observed:  # aucun en-tête réellement lu : on ne déduit pas ce qu'on n'a pas vu
        return _category("headers", [], evaluated=False)
    deductions = [
        (points, name)
        for name, points in HEADER_DEDUCTIONS.items()
        if name in observed and "Présent" not in observed[name]
    ]
    return _category("headers", deductions)


def _score_dns(scan, caps):
    dns_sec = scan.get("dns_security") or {}
    if not dns_sec:  # contrôles DNS non exécutés (scan interrompu, audit ancien)
        return _category("dns", [], evaluated=False)

    def status(key):
        info = dns_sec.get(key)
        return info.get("status") if isinstance(info, dict) else None

    deductions = []
    spf = dns_sec.get("spf") if isinstance(dns_sec.get("spf"), dict) else {}
    if status("spf") == "absent":
        deductions.append((25, "SPF absent"))
    elif status("spf") == "present" and spf.get("termination") == "+all":
        deductions.append((25, "SPF permissif (+all)"))

    dmarc = dns_sec.get("dmarc") if isinstance(dns_sec.get("dmarc"), dict) else {}
    if status("dmarc") == "absent":
        deductions.append((25, "DMARC absent"))
    elif status("dmarc") == "present" and dmarc.get("policy") == "none":
        deductions.append((12, "DMARC en p=none (surveillance seule)"))

    if status("axfr") == "vulnerable":
        deductions.append((30, "Transfert de zone AXFR ouvert"))
        caps.append((CAP_AXFR, "transfert de zone AXFR ouvert"))
    if status("dnssec") == "absent":
        deductions.append((12, "DNSSEC absent"))
    if status("caa") == "absent":
        deductions.append((8, "CAA absent"))
    return _category("dns", deductions)


def _parse_cookie(line):
    """'nom: ✅ Secure, HttpOnly, SameSite=Lax' -> (nom, secure, httponly, samesite)."""
    name, _, attrs = line.partition(": ")
    tokens = {t.strip() for t in attrs.replace("✅", "").replace("❌", "").split(",")}
    samesite = bool(tokens & {"SameSite=Lax", "SameSite=Strict"})
    return name, "Secure" in tokens, "HttpOnly" in tokens, samesite


def _score_cookies(scan):
    if scan.get("critical_failure") or scan.get("http_readable") is False:  # cookies jamais observés
        return _category("cookies", [], evaluated=False)
    cookies = [c for c in (scan.get("cookies_security") or []) if ": " in c]
    if not cookies:
        return _category("cookies", [])  # aucun cookie : rien à risque, 100

    lacks = {"secure": 0, "httponly": 0, "samesite": 0}
    for line in cookies:
        _name, secure, httponly, samesite = _parse_cookie(line)
        for k, ok in (("secure", secure), ("httponly", httponly), ("samesite", samesite)):
            lacks[k] += 0 if ok else 1

    labels = {"secure": "Secure", "httponly": "HttpOnly", "samesite": "SameSite"}
    deductions = [
        (COOKIE_WEIGHTS[k] * count / len(cookies) * 100,
         f"{labels[k]} manquant sur {count}/{len(cookies)} cookie(s)")
        for k, count in lacks.items() if count
    ]
    return _category("cookies", deductions)


def _infra_bonus(scan):
    """+5 par couche WAF/CDN distincte et réelle, plafonné à +10. Cache, routeur de plateforme et
    répartiteur de charge sont affichés mais ne comptent pas, même à côté d'un vrai WAF."""
    layers = scan.get("waf_layers")
    if isinstance(layers, list):
        names = {l.get("name") for l in layers if isinstance(l, dict) and l.get("protective")}
    else:  # anciens audits : chaîne « A + B »
        waf = str(scan.get("waf_detected") or "")
        names = {p for p in re.split(r"\s*(?:,|\+|&|;)\s*", waf) if p and "Non détecté" not in p}
    names -= NON_PROTECTIVE_LAYERS
    return min(INFRA_BONUS_PER_LAYER * len(names), INFRA_BONUS_MAX)


def _grade(score):
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _legacy_details(categories, bonus, cap):
    """Représentation dégradée pour l'ancien dashboard : lignes '-N pts: libellé'."""
    lines = []
    for key, cat in categories.items():
        if not cat.get("evaluated", True):
            lines.append(f"Note {cat['label']}: non évaluée (poids {cat['weight']}%)")
            continue
        lines.append(f"Note {cat['label']}: {cat['score']}/100 (poids {cat['weight']}%)")
        # Les en-têtes gardent leur nom court (HSTS, CSP...) : le dashboard s'en sert comme clé.
        lines.extend(f"-{d['points']} pts: {d['label']}" for d in cat["deductions"])
    if bonus:
        lines.append(f"+{bonus} pts: Bonus infrastructure (WAF/CDN détecté)")
    if cap:
        lines.append(f"Plafond appliqué: {cap['grade']} ({cap['max']}/100) - {'; '.join(cap['reasons'])}")
    return lines


def calculate_trust_score(scan_results):
    """Retourne numeric, letter, le détail par catégorie et une vue dégradée (details)."""
    caps = []
    if scan_results.get("critical_failure"):
        caps.append((CAP_HTTP_CLEAR, failure_label(scan_results)))

    categories = {
        "tls": _score_tls(scan_results, caps),
        "headers": _score_headers(scan_results),
        "dns": _score_dns(scan_results, caps),
        "cookies": _score_cookies(scan_results),
    }

    # VERDICT PARTIEL : une catégorie n'a pas pu être lue (challenge WAF, réponse HTTP non lue, DNS non
    # exécuté...) sans que le scan soit interrompu. On décrit, on ne note pas : aucune note globale et
    # surtout aucune moyenne re-normalisée sur les seules catégories restantes (elle récompenserait le
    # site qui bloque l'analyse). Les notes par catégorie, elles, restent celles qui ont été mesurées.
    if not scan_results.get("critical_failure") and any(not c["evaluated"] for c in categories.values()):
        return {
            "numeric": None,
            "letter": None,
            "categories": categories,
            "infra_bonus": 0,
            "raw_score": None,
            "cap": None,
            "partial": True,
            "details": _legacy_details(categories, 0, None),
        }

    # Moyenne pondérée sur les catégories évaluées seulement (poids renormalisés).
    measured = [c for c in categories.values() if c["evaluated"]]
    total_weight = sum(c["weight"] for c in measured)
    bonus = _infra_bonus(scan_results) if measured else 0
    if total_weight:
        weighted = sum(c["score"] * c["weight"] for c in measured) / total_weight
        raw_score = min(100, round(weighted + bonus))
    else:  # rien n'a été mesuré : le verdict est celui du plafond seul
        raw_score = min((c[0] for c in caps), default=0)

    cap = None
    score = raw_score
    if caps:
        limit = min(c[0] for c in caps)
        if limit < raw_score:
            score = limit
            cap = {"max": limit, "grade": _grade(limit),
                   "reasons": [reason for value, reason in caps if value == limit]}

    return {
        "numeric": score,
        "letter": _grade(score),
        "categories": categories,
        "infra_bonus": bonus,
        "raw_score": raw_score,
        "cap": cap,
        "partial": False,
        "details": _legacy_details(categories, bonus, cap),
    }
