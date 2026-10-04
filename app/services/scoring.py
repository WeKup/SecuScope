"""Scoring v2 : 4 catégories notées /100, moyenne pondérée, bonus infra, caps.

Voir docs/SCORING_V2_SPEC.md. Chaque catégorie part de 100 et déduit pour
chaque problème observé (plancher 0). Un contrôle non vérifié (erreur,
timeout, clé absente) ne déduit rien : on ne punit pas ce qu'on n'a pas vu.
"""
import re

WEIGHTS = {"tls": 35, "headers": 25, "dns": 25, "cookies": 15}
CATEGORY_LABELS = {"tls": "TLS/SSL", "headers": "En-têtes HTTP", "dns": "DNS", "cookies": "Cookies"}

INFRA_BONUS_PER_LAYER = 5
INFRA_BONUS_MAX = 10

CAP_HTTP_CLEAR = 20
CAP_BAD_CERT = 59
CAP_LEGACY_SSL = 79
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


def _category(key, deductions):
    """deductions : liste de (points, libellé). Retourne le bloc d'une catégorie."""
    total = sum(points for points, _label in deductions)
    return {
        "label": CATEGORY_LABELS[key],
        "weight": WEIGHTS[key],
        "score": max(0, round(100 - total)),
        "deductions": [{"points": round(p), "label": label} for p, label in deductions],
    }


def _score_tls(scan, caps):
    deductions = []
    if not scan.get("critical_failure") and not scan.get("ssl", {}).get("valid"):
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
    deductions = [
        (points, name)
        for name, points in HEADER_DEDUCTIONS.items()
        if "Présent" not in str(statuses.get(name, ""))
    ]
    return _category("headers", deductions)


def _score_dns(scan, caps):
    dns_sec = scan.get("dns_security") or {}

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
    waf = str(scan.get("waf_detected") or "")
    if not waf or "Non détecté" in waf:
        return 0
    layers = [p for p in re.split(r"\s*(?:,|\+|&|;)\s*", waf) if p]
    return min(INFRA_BONUS_PER_LAYER * len(layers), INFRA_BONUS_MAX)


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
        caps.append((CAP_HTTP_CLEAR, "HTTP en clair, HTTPS non forcé ou connexion TLS impossible"))

    categories = {
        "tls": _score_tls(scan_results, caps),
        "headers": _score_headers(scan_results),
        "dns": _score_dns(scan_results, caps),
        "cookies": _score_cookies(scan_results),
    }

    weighted = sum(c["score"] * c["weight"] for c in categories.values()) / 100
    bonus = _infra_bonus(scan_results)
    raw_score = min(100, round(weighted + bonus))

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
        "details": _legacy_details(categories, bonus, cap),
    }
