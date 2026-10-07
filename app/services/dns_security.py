"""Analyse de sécurité DNS : SPF, DMARC, DKIM, DNSSEC, CAA, AXFR.

Requêtes DNS standard uniquement (pas de brute-force : les sélecteurs DKIM
sont une liste fermée). Chaque contrôle est isolé : un échec est journalisé
et renvoie ``status: "error"`` sans affecter les autres ni le score.
"""
import logging
from concurrent.futures import ThreadPoolExecutor

import dns.exception
import dns.query
import dns.resolver
import dns.zone

from app.services.scanner import DNS_RESOLVERS, DNS_TIMEOUT, _build_resolver, _is_public_ip

logger = logging.getLogger(__name__)

DKIM_SELECTORS = ("google", "default", "selector1", "selector2", "k1", "dkim")
MAX_AXFR_NAMESERVERS = 5


def _resolver():
    return _build_resolver()  # résolveurs publics partagés avec le scanner


def _resolve(name, record_type):
    """Retourne les rdata, ou [] si l'enregistrement n'existe pas.

    Timeout et SERVFAIL remontent : « absent » ≠ « injoignable », sinon un
    résolveur lent infligerait un malus à tort (le contrôle passe en `error`).
    """
    try:
        return list(_resolver().resolve(name, record_type))
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []


def _txt_records_per_resolver(name):
    """TXT vus par CHAQUE résolveur configuré. Un résolveur peut tronquer une grosse réponse : on ne
    conclut à l'absence d'un enregistrement que si aucun d'eux ne le voit."""
    texts = []
    for nameserver in (DNS_RESOLVERS or [None]):
        resolver = _build_resolver()
        if nameserver:
            resolver.nameservers = [nameserver]
        try:
            texts += [b"".join(r.strings).decode("utf-8", errors="replace") for r in resolver.resolve(name, "TXT")]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            continue
    return texts


def _txt_records(name):
    return [
        b"".join(rdata.strings).decode("utf-8", errors="replace")
        for rdata in _resolve(name, "TXT")
    ]


# -------------------------------------------------------------------
# CONTRÔLES
# -------------------------------------------------------------------

def _check_spf(domain):
    spf = next(
        (t for t in _txt_records(domain) if t.lower().startswith("v=spf1")), None
    )
    if spf is None:  # recoupement : un résolveur qui tronque la réponse ne doit pas fabriquer un « absent »
        spf = next((t for t in _txt_records_per_resolver(domain) if t.lower().startswith("v=spf1")), None)
    if spf is None:
        return {"status": "absent", "record": None, "termination": None,
                "details": ["-10 pts: SPF absent"]}

    tokens = spf.lower().split()
    termination = "none"
    for token in tokens[1:]:
        if token in ("-all", "~all", "?all"):
            termination = token
        elif token in ("+all", "all"):
            termination = "+all"
        elif token.startswith("redirect=") and termination == "none":
            termination = "redirect"

    details = []
    if termination == "+all":
        details.append("-10 pts: SPF permissif (+all)")
    elif termination == "-all":
        details.append("+5 pts: SPF strict (-all)")
    return {"status": "present", "record": spf, "termination": termination,
            "details": details}


def _check_dmarc(domain):
    dmarc = next(
        (t for t in _txt_records(f"_dmarc.{domain}")
         if t.lower().startswith("v=dmarc1")), None
    )
    if dmarc is None:
        return {"status": "absent", "record": None, "policy": None,
                "details": ["-15 pts: DMARC absent"]}

    policy = None
    for part in dmarc.split(";"):
        key, _, value = part.strip().partition("=")
        if key.strip().lower() == "p":
            policy = value.strip().lower()
            break

    details = []
    if policy == "none":
        details.append("-5 pts: DMARC en mode none (p=none)")
    return {"status": "present", "record": dmarc, "policy": policy,
            "details": details}


def _check_dkim(domain):
    """Informatif : sélecteurs connus uniquement, aucun point."""
    found = []
    for selector in DKIM_SELECTORS:
        records = _txt_records(f"{selector}._domainkey.{domain}")
        if any("p=" in r.lower() or "v=dkim1" in r.lower() for r in records):
            found.append(selector)
    return {"status": "present" if found else "not_found",
            "selectors_found": found,
            "selectors_tested": list(DKIM_SELECTORS), "details": []}


def _check_dnssec(domain):
    enabled = bool(_resolve(domain, "DNSKEY") or _resolve(domain, "DS"))
    return {"status": "present" if enabled else "absent", "enabled": enabled,
            "details": ["+10 pts: DNSSEC actif"] if enabled else []}


def _check_caa(domain):
    authorities = []
    for rdata in _resolve(domain, "CAA"):
        tag = rdata.tag.decode("ascii", errors="replace").lower()
        if tag in ("issue", "issuewild"):
            value = rdata.value.decode("utf-8", errors="replace").strip()
            if value and value not in authorities:
                authorities.append(value)
    present = bool(authorities)
    return {"status": "present" if present else "absent",
            "authorities": authorities,
            "details": ["+5 pts: Enregistrement CAA présent"] if present else []}


def _try_axfr(ns_name, ns_ip, domain):
    try:
        zone = dns.zone.from_xfr(
            dns.query.xfr(ns_ip, domain, timeout=DNS_TIMEOUT, lifetime=DNS_TIMEOUT)
        )
        return bool(zone.nodes)
    except (dns.exception.DNSException, OSError, EOFError):
        return False


def _check_axfr(domain):
    targets = []
    for ns in _resolve(domain, "NS")[:MAX_AXFR_NAMESERVERS]:
        ns_name = ns.to_text().rstrip(".")
        for a in _resolve(ns_name, "A")[:1]:
            ip = a.to_text()
            if _is_public_ip(ip):  # anti-SSRF : jamais d'AXFR vers une IP interne
                targets.append((ns_name, ip))

    vulnerable = []
    if targets:
        with ThreadPoolExecutor(max_workers=len(targets)) as ex:
            results = list(ex.map(lambda t: _try_axfr(t[0], t[1], domain), targets))
        vulnerable = [t[0] for t, ok in zip(targets, results) if ok]

    return {"status": "vulnerable" if vulnerable else "refused",
            "vulnerable_nameservers": vulnerable,
            "nameservers_tested": [t[0] for t in targets],
            "details": ["-20 pts: Transfert de zone AXFR autorisé"] if vulnerable else []}


# -------------------------------------------------------------------
# ORCHESTRATION
# -------------------------------------------------------------------

_CHECKS = (
    ("spf", _check_spf),
    ("dmarc", _check_dmarc),
    ("dkim", _check_dkim),
    ("dnssec", _check_dnssec),
    ("caa", _check_caa),
    ("axfr", _check_axfr),
)


def analyze_dns_security(domain):
    """Exécute les 6 contrôles ; retourne un dict par contrôle + `score_details`."""
    result = {}
    score_details = []
    for key, check in _CHECKS:
        try:
            outcome = check(domain)
        except Exception:  # un contrôle ne doit jamais casser le scan
            logger.exception("Contrôle DNS '%s' en échec pour %s", key, domain)
            outcome = {"status": "error", "details": []}
        score_details.extend(outcome.pop("details", []))
        result[key] = outcome
    result["score_details"] = score_details
    return result
