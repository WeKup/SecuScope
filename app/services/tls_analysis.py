"""Analyse TLS approfondie via sslyze : versions, cipher suites, forward secrecy.

Ne re-score ni le certificat ni l'autorité (déjà traités par `get_ssl_info`).
Les vulnérabilités connues (Heartbleed, ROBOT, CCS injection) sont
informatives : aucun point. Un échec sslyze renvoie `status: "error"` sans
points et sans casser le scan.
"""
import logging
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout

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

TLS_SCAN_BUDGET = 18       # budget total de l'analyse sslyze (s) ; au-delà on garde ce qui est terminé
TLS_RETRY_WINDOW = 6       # durée max du retry ciblé 1.2/1.3 (s), pris sur le budget
TLS_NETWORK_TIMEOUT = 5    # timeout de connexion sslyze (s)
TLS_NETWORK_RETRIES = 0    # le seul retry est le passage ciblé 1.2/1.3 (voir _run_sslyze)
TLS_CONCURRENCY = 8        # connexions simultanées vers la cible
TLS_CONNECT_PRECHECK = 4   # test TCP du port 443 avant sslyze (s)

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


def _request(domain, ip, command):
    return ServerScanRequest(
        server_location=ServerNetworkLocation(hostname=domain, port=443, ip_address=ip),
        network_configuration=ServerNetworkConfiguration(
            tls_server_name_indication=domain,
            network_timeout=TLS_NETWORK_TIMEOUT,
            network_max_retries=TLS_NETWORK_RETRIES,
        ),
        scan_commands={command},
    )


class _CollectedAttempts:
    """Résultats des commandes terminées, lisibles par attribut comme un AllScanCommandsAttempts.
    Une commande absente (non terminée à l'échéance) vaut None : indéterminé, jamais « refusé »."""

    def __init__(self):
        self._attempts = {}

    def add(self, scan_result):
        for attr in vars(scan_result):
            attempt = getattr(scan_result, attr)
            status = getattr(attempt, "status", None)
            if status is not None and status != ScanCommandAttemptStatusEnum.NOT_SCHEDULED:
                self._attempts[attr] = attempt

    def has_completed(self, attr):
        return _completed(self._attempts.get(attr))

    def __getattr__(self, name):
        return self._attempts.get(name)


def _collect(domain, ip, commands, timeout, into):
    """Un scan sslyze par commande ; ajoute à `into` celles terminées avant `timeout` secondes.

    Un scan par commande donne des résultats partiels exploitables à l'échéance, au lieu de tout
    perdre quand le total dépasse le budget. Renvoie False si le serveur est injoignable."""
    scanner = Scanner(per_server_concurrent_connections_limit=TLS_CONCURRENCY)
    scanner.queue_scans([_request(domain, ip, c) for c in commands])
    reachable = [True]

    def consume():
        for result in scanner.get_results():
            if result.scan_status != ServerScanStatusEnum.COMPLETED:
                reachable[0] = False
                continue
            into.add(result.scan_result)

    worker = threading.Thread(target=consume, daemon=True, name=f"sslyze-{domain}")
    worker.start()
    worker.join(timeout)  # à l'échéance, le thread est abandonné (daemon) : son travail restant se termine seul
    return reachable[0]


def _log_failures(domain, attempts, tag):
    """Raison des échecs sslyze : dans les logs uniquement, jamais en base ni côté utilisateur."""
    for _label, _command, attr in _PROTOCOLS:
        attempt = getattr(attempts, attr)
        if attempt is not None and attempt.status == ScanCommandAttemptStatusEnum.ERROR:
            logger.warning("sslyze %s %s: %s en échec (%s)", tag, domain, attr,
                           getattr(attempt, "error_reason", "?"))


def _port_443_open(ip):
    """Évite de lancer sslyze sur un site sans HTTPS."""
    try:
        with socket.create_connection((ip, 443), timeout=TLS_CONNECT_PRECHECK):
            return True
    except OSError:
        return False


def _run_sslyze(domain, ip):
    started = time.monotonic()
    if not _port_443_open(ip):
        logger.info("sslyze %s : port 443 injoignable (%.1fs)", domain, time.monotonic() - started)
        return {"status": "unreachable", "details": []}

    commands = [c for _l, c, _a in _PROTOCOLS] + list(_VULN_COMMANDS)
    attempts = _CollectedAttempts()
    pass1_budget = TLS_SCAN_BUDGET - TLS_RETRY_WINDOW
    _collect(domain, ip, commands, pass1_budget, attempts)
    pass1 = time.monotonic() - started

    # Un seul retry, ciblé sur les protocoles porteurs de PFS (1.2/1.3) non aboutis : ce sont eux qui
    # conditionnent la note. Un protocole legacy qui expire est le plus souvent simplement refusé.
    failed = [c for label, c, a in _PROTOCOLS
              if label in _PFS_PROTOCOLS and not attempts.has_completed(a)]
    _log_failures(domain, attempts, "1er passage")
    if failed and pass1 < TLS_SCAN_BUDGET - 2:
        _collect(domain, ip, failed, min(TLS_RETRY_WINDOW, TLS_SCAN_BUDGET - pass1), attempts)

    done = [a for _l, _c, a in _PROTOCOLS if attempts.has_completed(a)]
    logger.info("sslyze %s : %d/%d protocoles analysés en %.1fs", domain, len(done), len(_PROTOCOLS),
                time.monotonic() - started)
    if not done:  # aucun protocole mesuré : l'analyse approfondie est inexploitable
        return {"status": "timeout", "details": []}
    return _evaluate(attempts)


def analyze_tls_deep(domain):
    """Analyse TLS de `domain`:443 ; ne lève jamais, renvoie toujours un dict, borne dure en durée."""
    try:
        # Anti-SSRF : on scanne une IP publique résolue ici, jamais le nom (pas de rebinding).
        ip = next((i for i in _resolve_records(domain, "A") if _is_public_ip(i)), None)
        if ip is None:
            return {"status": "skipped", "details": []}

        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(_run_sslyze, domain, ip)
        try:
            return future.result(timeout=TLS_SCAN_BUDGET + 4)  # filet de sécurité, _run_sslyze se borne seul
        except FutureTimeout:
            logger.warning("Analyse TLS approfondie abandonnée pour %s (> %ss)", domain, TLS_SCAN_BUDGET + 4)
            return {"status": "timeout", "details": []}
        finally:
            executor.shutdown(wait=False)  # ne pas bloquer le scan sur un sslyze lent
    except Exception:  # un échec TLS ne doit jamais casser le scan
        logger.exception("Analyse TLS approfondie en échec pour %s", domain)
        return {"status": "error", "details": []}
