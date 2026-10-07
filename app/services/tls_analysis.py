"""Analyse TLS approfondie via sslyze : versions, cipher suites, forward secrecy.

Ne re-score ni le certificat ni l'autorité (déjà traités par `get_ssl_info`).
Les vulnérabilités connues (Heartbleed, ROBOT, CCS injection) sont
informatives : aucun point. Un échec sslyze renvoie `status: "error"` sans
points et sans casser le scan.
"""
import logging
import time
from concurrent.futures import ThreadPoolExecutor

from sslyze import (
    ScanCommand,
    ScanCommandAttemptStatusEnum,
    Scanner,
    ServerNetworkConfiguration,
    ServerNetworkLocation,
    ServerScanRequest,
    ServerScanStatusEnum,
)

from app.services.scanner import _is_public_ip, _resolve_records

logger = logging.getLogger(__name__)

TLS_SCAN_TIMEOUT = 40      # budget global (s) ; au-delà on abandonne l'analyse
TLS_NETWORK_TIMEOUT = 7    # timeout de connexion sslyze (s)
TLS_NETWORK_RETRIES = 1
TLS_RETRY_MAX_ELAPSED = 20  # pas de 2e passe au-delà (s) : borne le coût total

# (clé de résultat, ScanCommand, attribut de AllScanCommandsAttempts)
_PROTOCOLS = (
    ("SSLv2", ScanCommand.SSL_2_0_CIPHER_SUITES, "ssl_2_0_cipher_suites"),
    ("SSLv3", ScanCommand.SSL_3_0_CIPHER_SUITES, "ssl_3_0_cipher_suites"),
    ("TLSv1.0", ScanCommand.TLS_1_0_CIPHER_SUITES, "tls_1_0_cipher_suites"),
    ("TLSv1.1", ScanCommand.TLS_1_1_CIPHER_SUITES, "tls_1_1_cipher_suites"),
    ("TLSv1.2", ScanCommand.TLS_1_2_CIPHER_SUITES, "tls_1_2_cipher_suites"),
    ("TLSv1.3", ScanCommand.TLS_1_3_CIPHER_SUITES, "tls_1_3_cipher_suites"),
)
_VULN_COMMANDS = (ScanCommand.HEARTBLEED, ScanCommand.ROBOT,
                  ScanCommand.OPENSSL_CCS_INJECTION)

# Jetons de nom de suite (ex. TLS_RSA_WITH_3DES_EDE_CBC_SHA → {"RSA","WITH","3DES",...}).
# HMAC-SHA1 n'est volontairement pas listé : quasi toutes les suites CBC TLS 1.2
# l'utilisent, ce n'est pas un défaut exploitable.
_WEAK_TOKENS = {"RC4": "RC4", "DES": "DES", "3DES": "3DES", "EXPORT": "EXPORT",
                "NULL": "NULL", "MD5": "MD5", "ANON": "ANON"}
_PFS_TOKENS = {"ECDHE", "DHE"}
_PFS_PROTOCOLS = {"TLSv1.2", "TLSv1.3"}  # seuls porteurs de forward secrecy


def _completed(attempt):
    return attempt is not None and attempt.status == ScanCommandAttemptStatusEnum.COMPLETED


def _weak_reasons(cipher):
    tokens = set(cipher.cipher_suite.name.upper().replace("-", "_").split("_"))
    reasons = {label for token, label in _WEAK_TOKENS.items() if token in tokens}
    if cipher.cipher_suite.is_anonymous:
        reasons.add("ANON")
    return reasons


def _evaluate(attempts):
    """Transforme les résultats sslyze en dict + lignes de score (sans I/O)."""
    protocols, weak, pfs = {}, set(), False
    for label, _command, attr in _PROTOCOLS:
        attempt = getattr(attempts, attr)
        if not _completed(attempt):
            protocols[label] = None  # indéterminé
            continue
        accepted = attempt.result.accepted_cipher_suites
        protocols[label] = bool(accepted)
        for cipher in accepted:
            weak |= _weak_reasons(cipher)
            tokens = set(cipher.cipher_suite.name.upper().split("_"))
            if label == "TLSv1.3" or tokens & _PFS_TOKENS:
                pfs = True

    vulns = {}
    for name, attr, extract in (
        ("heartbleed", "heartbleed", lambda r: r.is_vulnerable_to_heartbleed),
        ("ccs_injection", "openssl_ccs_injection",
         lambda r: r.is_vulnerable_to_ccs_injection),
        ("robot", "robot", lambda r: r.robot_result.value.startswith("VULNERABLE")),
    ):
        attempt = getattr(attempts, attr)
        vulns[name] = bool(extract(attempt.result)) if _completed(attempt) else None

    # Forward secrecy : True dès qu'une suite PFS est observée. False uniquement si les deux
    # protocoles qui la portent (1.2 et 1.3) ont été analysés sans en trouver. Sinon indéterminé :
    # un contrôle non vérifié ne doit jamais devenir une faille.
    if pfs:
        forward_secrecy = True
    elif protocols["TLSv1.2"] is not None and protocols["TLSv1.3"] is not None:
        forward_secrecy = False
    else:
        forward_secrecy = None

    details = []
    if protocols["SSLv2"] or protocols["SSLv3"]:
        details.append("-20 pts: Protocole obsolète accepté (SSLv2/SSLv3)")
    if protocols["TLSv1.0"] or protocols["TLSv1.1"]:
        details.append("-10 pts: Protocole déprécié accepté (TLS 1.0/1.1)")
    if weak:
        details.append("-15 pts: Cipher suite faible détectée")
    if forward_secrecy is False:
        details.append("-10 pts: Forward Secrecy absente")
    if protocols["TLSv1.3"]:
        details.append("+5 pts: TLS 1.3 supporté")

    return {
        "status": "ok",
        "protocols": protocols,
        "weak_ciphers": sorted(weak),
        "forward_secrecy": forward_secrecy,
        "vulnerabilities": vulns,
        "details": details,
    }


def _scan(domain, ip, commands):
    """Un passage sslyze sur `commands` ; renvoie le résultat de serveur."""
    request = ServerScanRequest(
        server_location=ServerNetworkLocation(hostname=domain, port=443, ip_address=ip),
        network_configuration=ServerNetworkConfiguration(
            tls_server_name_indication=domain,
            network_timeout=TLS_NETWORK_TIMEOUT,
            network_max_retries=TLS_NETWORK_RETRIES,
        ),
        scan_commands=set(commands),
    )
    scanner = Scanner(per_server_concurrent_connections_limit=5)
    scanner.queue_scans([request])
    return next(scanner.get_results())


class _MergedAttempts:
    """Résultats du 1er passage, complétés par ceux du retry quand ils ont abouti."""

    def __init__(self, first, retry):
        self._first, self._retry = first, retry

    def __getattr__(self, name):
        if self._retry is not None:
            attempt = getattr(self._retry, name, None)
            if _completed(attempt):
                return attempt
        return getattr(self._first, name)


def _log_failures(domain, attempts, tag):
    """Raison des échecs sslyze : dans les logs uniquement, jamais en base ni côté utilisateur."""
    for _label, _command, attr in _PROTOCOLS:
        attempt = getattr(attempts, attr)
        if attempt is not None and attempt.status == ScanCommandAttemptStatusEnum.ERROR:
            logger.warning("sslyze %s %s: %s en échec (%s)", tag, domain, attr,
                           getattr(attempt, "error_reason", "?"))


def _run_sslyze(domain, ip):
    started = time.monotonic()
    commands = {c for _l, c, _a in _PROTOCOLS} | set(_VULN_COMMANDS)
    result = _scan(domain, ip, commands)
    if result.scan_status != ServerScanStatusEnum.COMPLETED:
        return {"status": "unreachable", "details": []}

    attempts = result.scan_result
    _log_failures(domain, attempts, "1er passage")
    # Un seul retry, limité aux protocoles porteurs de PFS (1.2/1.3) non aboutis : ce sont eux qui
    # conditionnent la note. Un protocole legacy qui expire est le plus souvent simplement refusé.
    failed = {c for label, c, a in _PROTOCOLS
              if label in _PFS_PROTOCOLS and not _completed(getattr(attempts, a))}
    if failed:
        if time.monotonic() - started < TLS_RETRY_MAX_ELAPSED:
            retry = _scan(domain, ip, failed)
            if retry.scan_status == ServerScanStatusEnum.COMPLETED:
                attempts = _MergedAttempts(attempts, retry.scan_result)
                _log_failures(domain, retry.scan_result, "retry")
    return _evaluate(attempts)


def analyze_tls_deep(domain):
    """Analyse TLS de `domain`:443 ; ne lève jamais, renvoie toujours un dict."""
    try:
        # Anti-SSRF : on scanne une IP publique résolue ici, jamais le nom (pas de rebinding).
        ip = next((i for i in _resolve_records(domain, "A") if _is_public_ip(i)), None)
        if ip is None:
            return {"status": "skipped", "details": []}

        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(_run_sslyze, domain, ip)
        try:
            return future.result(timeout=TLS_SCAN_TIMEOUT)
        finally:
            executor.shutdown(wait=False)  # ne pas bloquer le scan sur un sslyze lent
    except Exception:  # un échec TLS ne doit jamais casser le scan
        logger.exception("Analyse TLS approfondie en échec pour %s", domain)
        return {"status": "error", "details": []}
