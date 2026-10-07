from curl_cffi import requests
import logging
import re
import time
from contextlib import contextmanager
import ssl
import socket
import dns.resolver
import dns.reversename
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
import ipaddress
from http.cookies import SimpleCookie
from urllib.parse import urlparse
from app.services.signature import (
    NON_PROTECTIVE_LAYERS,
    SECURITY_HEADERS,
    TECH_SIGNATURES,
    WAF_SIGNATURES,
)

logger = logging.getLogger(__name__)

# --- CONFIGURATION ---
DNS_TIMEOUT = 3
TCP_TIMEOUT = 3
HTTP_TIMEOUT = 8
LIGHT_WAF_TIMEOUT = 4
WAFW00F_TIMEOUT = 12   # sonde wafw00f en dernier recours : abandonnée passé ce délai (s), incluse dans le budget du scan
SCAN_BUDGET = 40       # budget global d'un scan (s) : au-delà, les composants non terminés sont abandonnés
UA_CHROME = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

try:
    from wafw00f.main import WAFW00F  # v2.2.0 : la classe s'écrit WAFW00F
    WAFW00F_AVAILABLE = True
    logging.getLogger("wafw00f").setLevel(logging.WARNING)  # il loggue chaque signature testée en INFO
except ImportError:
    WAFW00F_AVAILABLE = False


# -------------------------------------------------------------------
# UTILS
# -------------------------------------------------------------------

class _Timings(dict):
    """Durée (s) de chaque phase d'un scan, loggée en fin d'analyse pour diagnostiquer la lenteur."""

    @contextmanager
    def phase(self, name):
        started = time.perf_counter()
        try:
            yield
        finally:
            self[name] = round(time.perf_counter() - started, 2)

    def summary(self):
        return " ".join(f"{k}={v}s" for k, v in self.items())


def _build_resolver():
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    return resolver


def _resolve_records(domain, record_type):
    try:
        answers = _build_resolver().resolve(domain, record_type)
        return [answer.to_text() for answer in answers]
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return []


def _normalize_host(value):
    return str(value).lower().rstrip(".")


def _is_public_ip(ip):
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return False

    return not any((
        parsed.is_private,
        parsed.is_loopback,
        parsed.is_link_local,
        parsed.is_multicast,
        parsed.is_reserved,
        parsed.is_unspecified,
    ))


def _has_only_public_ips(dns_info):
    return bool(dns_info.get("ips")) and all(_is_public_ip(ip) for ip in dns_info["ips"])


def get_headers():
    return {
        "User-Agent": UA_CHROME,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    }


def check_tcp_port(domain, port=443):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TCP_TIMEOUT)
            return s.connect_ex((domain, port)) == 0
    except Exception:
        return False


# -------------------------------------------------------------------
# WAF DETECTION
# -------------------------------------------------------------------

def _value_has_token(value, token):
    """Le jeton figure dans la valeur d'en-tête comme mot entier (« gws » ≠ « gwsfoo »)."""
    return re.search(rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])", value) is not None


def _provider_matches(sigs, headers_lower, cookie_names, body_lower, cnames):
    """Un fournisseur est présent si UN de ses signaux honnêtes correspond (voir signature.py)."""
    if any(h in headers_lower for h in sigs.get("headers", [])):
        return True
    if any(name.startswith(pre) for name in headers_lower for pre in sigs.get("header_prefixes", [])):
        return True
    for header, tokens in sigs.get("header_values", {}).items():
        if any(_value_has_token(headers_lower.get(header, ""), t) for t in tokens):
            return True
    if any(name.startswith(pre) for name in cookie_names for pre in sigs.get("cookies", [])):
        return True
    if any(marker in body_lower for marker in sigs.get("body", [])):
        return True
    # CNAME : le signal le plus fiable (« qui protège ce site »). Pas de NS ni de PTR.
    return any(token in cname for cname in cnames for token in sigs.get("cname", []))


def _identify_waf_layers(headers, cookies, body, dns_info):
    """TOUTES les couches WAF/CDN détectées, une seule entrée par fournisseur.

    On ne s'arrête pas au premier match : un même site peut avoir plusieurs couches (ex. Akamai en
    CNAME + Azure Front Door en en-tête). Plusieurs signaux d'un même fournisseur = une seule couche."""
    headers_lower = {str(k).lower(): str(v).lower() for k, v in headers.items()}
    cookie_names = [str(k).lower() for k in cookies.keys()]
    body_lower = body.lower() if body else ""
    cnames = [str(c).lower().rstrip(".") for c in dns_info.get("cname", [])]
    return [provider for provider, sigs in WAF_SIGNATURES.items()
            if _provider_matches(sigs, headers_lower, cookie_names, body_lower, cnames)]


def _canonical_layer(name):
    """Nom de fournisseur du référentiel pour un nom donné par wafw00f (dédoublonnage)."""
    low = name.lower()
    for provider, sigs in WAF_SIGNATURES.items():
        if any(alias in low for alias in sigs.get("aliases", [])):
            return provider
    return name


def _detect_tech(headers_lower, cookie_names):
    """Technologies lues dans Server / X-Powered-By, en-têtes dédiés et cookies : rien n'est deviné."""
    found = []
    for tech, sigs in TECH_SIGNATURES.items():
        by_value = any(_value_has_token(str(headers_lower.get(h, "")).lower(), t)
                       for h in ("server", "x-powered-by") for t in sigs.get(h, []))
        by_header = any(h in headers_lower for h in sigs.get("headers", []))
        by_cookie = any(name.startswith(pre) for name in cookie_names for pre in sigs.get("cookies", []))
        if by_value or by_header or by_cookie:
            found.append(tech)
    return found


def _run_wafw00f(https_url, domain):
    """Sonde active wafw00f, en DERNIER RECOURS (le passif n'a rien trouvé).

    Renvoie le nom du WAF, ou None (absent, échec ou délai dépassé). Elle tourne dans un thread
    borné par WAFW00F_TIMEOUT : à l'échéance on abandonne proprement, sans bloquer le scan."""
    def work():
        detected = WAFW00F(https_url).identwaf(findall=False)
        # « Cloudflare (Cloudflare Inc.) » -> « Cloudflare » : on garde le nom du produit
        return _canonical_layer(str(detected[0]).split(" (")[0].strip()) if detected else None

    executor = ThreadPoolExecutor(max_workers=1)
    try:
        return executor.submit(work).result(timeout=WAFW00F_TIMEOUT)
    except FutureTimeout:
        logger.warning("wafw00f abandonné sur %s (> %ss)", domain, WAFW00F_TIMEOUT)
    except Exception:
        logger.warning("wafw00f en échec sur %s", domain, exc_info=True)
    finally:
        executor.shutdown(wait=False)
    return None


# -------------------------------------------------------------------
# DNS
# -------------------------------------------------------------------

def _cname_chain(name, max_hops=5):
    """Chaîne de CNAME (jusqu'à `max_hops` sauts) : un CDN apparaît souvent au 2e saut."""
    chain, current = [], name
    for _ in range(max_hops):
        targets = _resolve_records(current, "CNAME")
        if not targets:
            break
        current = _normalize_host(targets[0])
        chain.append(current)
    return chain


def get_dns_info(domain):
    res = {
        "ip": "Inconnue",
        "ips": [],
        "ptr": "",
        "cname": [],
        "ns": [],
        "details": [],
        "error": False,
        "error_type": None,
    }
    try:
        resolver = _build_resolver()
        ipv4 = [answer.to_text() for answer in resolver.resolve(domain, "A")]
        ipv6 = _resolve_records(domain, "AAAA")

        res["ips"] = ipv4 + ipv6
        if not res["ips"]:
            res["error"] = True
            res["error_type"] = "NO_ADDRESS"
            res["details"].append("Domaine sans enregistrement A/AAAA exploitable")
            return res

        res["ip"] = res["ips"][0]

        try:
            rev = dns.reversename.from_address(res["ip"])
            res["ptr"] = _normalize_host(resolver.resolve(rev, "PTR")[0])
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            pass

        res["cname"] = _cname_chain(domain)
        res["ns"] = [_normalize_host(r) for r in _resolve_records(domain, "NS")]

    except dns.resolver.NXDOMAIN:
        res["details"].append("Domaine inexistant (NXDOMAIN)")
        res["error"] = True
        res["error_type"] = "NXDOMAIN"
    except dns.exception.Timeout:
        res["details"].append("Timeout DNS")
        res["error"] = True
        res["error_type"] = "TIMEOUT"
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        res["details"].append("Resolution DNS impossible")
        res["error"] = True
        res["error_type"] = "DNS_ERROR"
    return res


# -------------------------------------------------------------------
# SSL
# -------------------------------------------------------------------

def get_ssl_info(domain):
    result = {"valid": False, "issuer": "Inconnu", "expiry": "N/A", "details": [], "error_type": None}

    if not check_tcp_port(domain, 443):
        result["details"].append("-20 pts: Port 443 fermé")
        return result

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((domain, 443), timeout=HTTP_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert["issuer"])
                name = issuer.get("organizationName", issuer.get("commonName", "Inconnu"))

                result["valid"] = True
                result["issuer"] = name
                result["expiry"] = cert["notAfter"]
                result["details"].append("+20 pts: Certificat SSL valide")
                
                trusted = ["DigiCert", "GlobalSign", "Entrust", "Amazon", "Google", "Let's Encrypt", "Cloudflare", "Sectigo", "GTS"]
                if any(x.lower() in str(name).lower() for x in trusted):
                    result["details"].append("+5 pts: Autorité Reconnue")

    except ssl.SSLCertVerificationError:
        result["error_type"] = "ssl_mismatch"
        result["details"].append("-20 pts: Certificat invalide (expiré, non reconnu ou nom non concordant)")
    except ssl.SSLError:
        result["error_type"] = "ssl_invalid"
        result["details"].append("-20 pts: Négociation TLS échouée (protocole ou cipher incompatible)")
    except (socket.timeout, OSError):
        result["error_type"] = "connection_error"

    return result


# -------------------------------------------------------------------
# HTTP (V12 - Avec Check HTTPS Forcé)
# -------------------------------------------------------------------

def _merged_response_headers(resp):
    headers = {}
    if hasattr(resp, "history") and resp.history:
        for previous in resp.history:
            headers.update(dict(previous.headers))
    headers.update(dict(resp.headers))
    return headers


def _get_set_cookie_headers(headers):
    getter = getattr(headers, "get_list", None)
    if callable(getter):
        return getter("set-cookie") or getter("Set-Cookie")

    raw = headers.get("set-cookie") or headers.get("Set-Cookie")
    if not raw:
        return []

    # Fallback conservateur: evite de declarer tous les cookies OK a partir
    # d'un seul attribut Secure present sur un autre cookie.
    return [part.strip() for part in raw.split(", ") if "=" in part]


def _audit_cookies(resp):
    if not resp.cookies:
        return ["Aucun cookie"]

    cookie_headers = _get_set_cookie_headers(resp.headers)
    parsed_by_name = {}

    for header in cookie_headers:
        cookie = SimpleCookie()
        try:
            cookie.load(header)
        except Exception:
            continue
        for name, morsel in cookie.items():
            parsed_by_name[name] = {
                "secure": bool(morsel["secure"]),
                "httponly": bool(morsel["httponly"]),
                "samesite": morsel["samesite"],
            }

    results = []
    for name in resp.cookies.keys():
        attrs = parsed_by_name.get(name, {})
        secure = attrs.get("secure", False)
        httponly = attrs.get("httponly", False)
        status = []
        status.append("Secure" if secure else "Insecure")
        status.append("HttpOnly" if httponly else "No HttpOnly")
        samesite = attrs.get("samesite", "")
        status.append(f"SameSite={samesite.capitalize()}" if samesite else "No SameSite")
        icon = "✅" if secure and httponly else "❌"
        results.append(f"{name}: {icon} {', '.join(status)}")

    return results


def get_http_info(target_url, dns_info, domain):
    res = {
        "server": "Inconnu", "waf": "Non détecté", "headers": {}, "missing": [],
        "cookies": [], "details": [], "tech": [], "ssl_worked": False, "critical_failure": False,
        # failure : cause d'un arrêt anticipé ("http_clear" | "tls" | "cert") ; http_readable : réponse HTTPS lue
        "failure": None, "http_readable": False, "waf_layers": [],
    }

    session = requests.Session()
    timings = res["timings"] = _Timings()

    try:
        # 1. Test HTTPS Principal
        https_url = f"https://{domain}" if not target_url.startswith("https") else target_url
        with timings.phase("https_probe"):
            resp = session.get(
                https_url,
                headers=get_headers(),
                timeout=HTTP_TIMEOUT,
                allow_redirects=True,
                impersonate="chrome120",
            )
        all_headers = _merged_response_headers(resp)
        headers_lower = {k.lower(): v for k, v in all_headers.items()}

        # Vérification redirection inverse (HTTPS -> HTTP)
        if resp.url.startswith("https://"):
            res["ssl_worked"] = True
            res["http_readable"] = True
        else:
            res["critical_failure"] = True
            res["failure"] = "http_clear"
            res["details"].append("-100 pts: Redirection DANGEREUSE vers HTTP")
            return res

        # --- Technologies et en-têtes de sécurité (lecture locale de la réponse, instantané) ---
        res["server"] = resp.headers.get("Server") or "Inconnu"

        res["tech"] = _detect_tech(headers_lower, [str(k).lower() for k in resp.cookies.keys()])

        for h_real, h_name in SECURITY_HEADERS.items():
            if h_real.lower() in headers_lower:
                res["headers"][h_name] = "✅ Présent"
                res["details"].append(f"+5 pts: {h_name}")
            else:
                res["headers"][h_name] = "❌ Manquant"
                res["missing"].append(h_name)

        # --- Sondes réseau indépendantes, lancées en parallèle (chacune borne son propre délai) ---
        def probe_http_clear():
            """Le site répond-il aussi en clair, sans redirection vers HTTPS ? (Enforce SSL)"""
            try:
                with timings.phase("http_probe"):
                    http_resp = requests.get(f"http://{domain}", headers=get_headers(), timeout=LIGHT_WAF_TIMEOUT,
                                             allow_redirects=True, impersonate="chrome120")
                return http_resp.status_code < 400 and http_resp.url.startswith("http://")
            except requests.exceptions.RequestException:
                return False

        def detect_waf():
            """Passif (en-têtes, cookies, CNAME) : toutes les couches. wafw00f en dernier recours,
            seulement si le passif n'a trouvé aucun vrai WAF/CDN (un cache ne compte pas)."""
            with timings.phase("waf_signatures"):
                # CNAME du domaine saisi ET de l'hôte final après redirection (apple.com -> www.apple.com)
                final_host = (urlparse(resp.url).hostname or "").lower()
                cname_info = dict(dns_info)
                if final_host and final_host != domain:
                    cname_info["cname"] = list(dns_info.get("cname", [])) + _cname_chain(final_host)
                layers = _identify_waf_layers(all_headers, resp.cookies, resp.text, cname_info)
            if WAFW00F_AVAILABLE and all(layer in NON_PROTECTIVE_LAYERS for layer in layers):
                with timings.phase("wafw00f"):
                    extra = _run_wafw00f(https_url, domain)
                if extra and extra not in layers:
                    layers.append(extra)
            return layers

        def www_has_hsts():
            try:
                with timings.phase("hsts_www"):
                    www_resp = requests.get(f"https://www.{domain}", headers=get_headers(),
                                            timeout=LIGHT_WAF_TIMEOUT, impersonate="chrome120")
                return "strict-transport-security" in {k.lower() for k in www_resp.headers}
            except requests.exceptions.RequestException:
                return False

        # Pas de `with` : si le site répond en clair, on rend le verdict tout de suite sans attendre
        # la sonde WAF ni le test www (ils finissent seuls en arrière-plan, bornés).
        pool = ThreadPoolExecutor(max_workers=3)
        try:
            f_clear = pool.submit(probe_http_clear)
            f_waf = pool.submit(detect_waf)
            f_hsts = pool.submit(www_has_hsts) if "HSTS" in res["missing"] else None
            if f_clear.result():
                res["critical_failure"] = True
                res["failure"] = "http_clear"
                res["details"].append("-100 pts: 🚨 HTTPS NON FORCÉ (Site accessible en clair)")
                return res
            waf_layers = f_waf.result()
            www_hsts = f_hsts.result() if f_hsts else False
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

        res["waf"] = " + ".join(waf_layers) if waf_layers else "Non détecté"
        res["waf_layers"] = [{"name": n, "protective": n not in NON_PROTECTIVE_LAYERS} for n in waf_layers]
        if waf_layers:
            res["details"].append(f"WAF/CDN détecté ({res['waf']})")

        if www_hsts:
            res["headers"]["HSTS"] = "✅ Présent (www)"
            res["missing"].remove("HSTS")
            res["details"].append("+5 pts: HSTS")

        # Audit des Cookies
        res["cookies"] = _audit_cookies(resp)

    # --- GESTION DES ERREURS ---
    except (requests.exceptions.SSLError, requests.exceptions.ProxyError):
        # Handshake ou certificat : analyze_target tranche avec le diagnostic de get_ssl_info.
        res["critical_failure"] = True
        res["failure"] = "tls"
        res["details"].append("-100 pts: Échec de la connexion TLS")

    except requests.exceptions.ConnectionError:
        if not check_tcp_port(domain, 443):
            # Aucun HTTPS : si le site répond en clair, c'est du HTTP en clair, pas un site « inaccessible ».
            try:
                with timings.phase("http_probe"):
                    http_resp = requests.get(f"http://{domain}", headers=get_headers(), timeout=LIGHT_WAF_TIMEOUT,
                                             allow_redirects=True, impersonate="chrome120")
                served_in_clear = http_resp.status_code < 400 and http_resp.url.startswith("http://")
            except requests.exceptions.RequestException:
                served_in_clear = False
            if served_in_clear:
                res["critical_failure"], res["failure"] = True, "http_clear"
                res["details"].append("-100 pts: 🚨 Aucun HTTPS : site accessible en clair")
            else:
                res["details"].append("-50 pts: Site Inaccessible")
        else:
            # Le port 443 répond mais la requête HTTPS a échoué : on teste un handshake TLS standard.
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=LIGHT_WAF_TIMEOUT) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain):
                        pass
                # Handshake OK : seule la requête HTTP échoue (client refusé, connexion coupée...).
                # Rien n'a été lu : en-têtes et cookies sont non vérifiables, pas protégés.
                res["details"].append("Réponse HTTPS non lue : en-têtes et cookies non vérifiables")
            except ssl.SSLCertVerificationError:
                res["critical_failure"], res["failure"] = True, "cert"
                res["details"].append("-100 pts: Certificat TLS invalide")
            except ssl.SSLError:
                res["critical_failure"], res["failure"] = True, "tls"
                res["details"].append("-100 pts: Handshake TLS échoué")
            except (socket.timeout, OSError):
                res["details"].append("Connexion TLS impossible à établir : contrôles HTTP non vérifiables")

    except requests.exceptions.Timeout:
        res["details"].append("Délai HTTP dépassé : contrôles HTTP non vérifiables")
    except requests.exceptions.RequestException as e:
        logger.warning("Erreur HTTP sur %s : %s", domain, e)
        res["details"].append("Erreur HTTP : contrôles HTTP non vérifiables")

    return res

# -------------------------------------------------------------------
# MAIN ORCHESTRATOR
# -------------------------------------------------------------------

def is_safe_domain(ip: str) -> bool:
    return _is_public_ip(ip)

def _timed_call(fn, *args):
    """(résultat, durée en s) : mesure chaque composant exécuté en parallèle."""
    started = time.perf_counter()
    result = fn(*args)
    return result, round(time.perf_counter() - started, 2)


def _failure_kind(failure, ssl_d):
    """Cause d'un arrêt du scan : http_clear | tls_handshake | cert_invalid.

    Un handshake qui échoue (protocole ou cipher refusé, ex. RC4) n'est ni du HTTP en clair
    ni un certificat invalide : on s'appuie sur le diagnostic TLS standard pour trancher."""
    if failure == "http_clear":
        return "http_clear"
    if failure == "cert" or ssl_d.get("error_type") == "ssl_mismatch":
        return "cert_invalid"
    return "tls_handshake"


def analyze_target(domain):
    scan_started = time.perf_counter()
    deadline = scan_started + SCAN_BUDGET
    domain = domain.lower().strip()
    target_url = f"https://{domain}"

    dns_d, dns_time = _timed_call(get_dns_info, domain)

    if dns_d.get("error"):
        return {"error": "NXDOMAIN", "domain": domain, "scan_data": {"numeric_score": 0}}

    if not _has_only_public_ips(dns_d):
        return {"error": "PRIVATE_IP", "domain": domain}

    # Imports tardifs : ces modules réutilisent DNS_TIMEOUT, _is_public_ip... d'ici.
    from app.services.dns_security import analyze_dns_security
    from app.services.tls_analysis import analyze_tls_deep

    def result_of(future, name, fallback):
        """Résultat d'un composant, ou `fallback` s'il échoue / dépasse le budget global du scan."""
        try:
            return future.result(timeout=max(0.0, deadline - time.perf_counter()))
        except FutureTimeout:
            logger.warning("Scan %s : %s abandonné (budget de %ss dépassé)", domain, name, SCAN_BUDGET)
        except Exception:
            logger.exception("Scan %s : %s en échec", domain, name)
        return fallback, None

    # Pas de `with` : à la sortie on n'attend pas les threads en retard (ils finissent seuls).
    ex = ThreadPoolExecutor(max_workers=4)
    f_http = ex.submit(_timed_call, get_http_info, target_url, dns_d, domain)
    f_ssl = ex.submit(_timed_call, get_ssl_info, domain)
    f_dns_sec = ex.submit(_timed_call, analyze_dns_security, domain)
    f_tls_deep = ex.submit(_timed_call, analyze_tls_deep, domain)
    try:
        http_d, http_time = result_of(f_http, "http", {
            "server": "Inconnu", "waf": "Non détecté", "headers": {}, "missing": [], "cookies": [],
            "details": ["Délai dépassé : contrôles HTTP non vérifiables"], "tech": [], "ssl_worked": False,
            "critical_failure": False, "failure": None, "http_readable": False, "waf_layers": [],
        })
        ssl_d, ssl_time = result_of(f_ssl, "ssl", {
            "valid": False, "issuer": "Inconnu", "expiry": "N/A", "details": [], "error_type": "timeout",
        })

        # Le diagnostic TLS standard a échoué sans erreur de certificat et aucune requête HTTPS n'a abouti :
        # c'est un handshake impossible (protocole/cipher), pas un certificat invalide ni un site en clair.
        if (not http_d.get("critical_failure") and not http_d.get("ssl_worked")
                and ssl_d.get("error_type") == "ssl_invalid"):
            http_d["critical_failure"], http_d["failure"] = True, "tls"

        # KILL-SWITCH : pas de HTTPS exploitable. Inutile d'attendre sslyze ni le DNS : on répond vite.
        if http_d.get("critical_failure"):
            logger.info("Scan %s : arrêt anticipé (%s) en %ss", domain, http_d.get("failure"),
                        round(time.perf_counter() - scan_started, 2))
            return {
                "domain": domain, "ip": dns_d["ip"],
                "ssl": {"valid": False, "issuer": "Inconnu", "details": ssl_d["details"]},
                "waf_detected": "Non détecté", "server": "Inconnu",
                "headers": {}, "missing_headers": [],  # rien n'a été lu : aucun en-tête n'est déclaré manquant
                "cookies_security": [], "tech_stack": [],
                "score_details": http_d["details"],
                "critical_failure": True,
                "failure_kind": _failure_kind(http_d.get("failure"), ssl_d),
            }

        dns_sec, dns_sec_time = result_of(f_dns_sec, "dns_security", {"score_details": []})
        tls_deep, tls_time = result_of(f_tls_deep, "tls", {"status": "timeout", "details": []})
    finally:
        ex.shutdown(wait=False, cancel_futures=True)

    logger.info(
        "Scan %s : total=%ss | dns=%ss ssl_cert=%ss dns_security=%ss tls_sslyze=%ss http=%ss [%s]",
        domain, round(time.perf_counter() - scan_started, 2), dns_time, ssl_time, dns_sec_time, tls_time,
        http_time, http_d.get("timings", _Timings()).summary(),
    )

    # Le client HTTPS a validé le certificat alors que le diagnostic standard a échoué : on garde
    # l'émetteur réel (« Inconnu » si non lu), on ne le remplace par aucun nom inventé.
    if not ssl_d["valid"] and http_d["ssl_worked"] and ssl_d.get("error_type") != "ssl_mismatch":
        ssl_d.update({"valid": True, "details": ["+20 pts: SSL opérationnel"]})

    headers, missing = http_d["headers"], http_d["missing"]
    if not http_d["http_readable"]:  # réponse non lue : on ne prétend rien sur les en-têtes
        headers = {name: "⚪ Non vérifiable" for name in SECURITY_HEADERS.values()}
        missing = []

    return {
        "domain": domain,
        "ip": dns_d["ip"],
        "ssl": ssl_d,
        "waf_detected": http_d["waf"],
        "waf_layers": http_d.get("waf_layers", []),
        "server": http_d["server"],
        "headers": headers,
        "missing_headers": missing,
        "cookies_security": http_d.get("cookies", []),
        "http_readable": http_d["http_readable"],
        "tech_stack": list(dict.fromkeys(http_d["tech"])),
        "dns_security": {k: v for k, v in dns_sec.items() if k != "score_details"},
        "tls_deep": {k: v for k, v in tls_deep.items() if k != "details"},
        "score_details": (
            dns_d["details"] + ssl_d["details"] + http_d["details"]
            + dns_sec["score_details"] + tls_deep["details"]
        ),
    }
