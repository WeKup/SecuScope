from curl_cffi import requests
import ssl
import socket
import dns.resolver
import dns.reversename
from concurrent.futures import ThreadPoolExecutor
import ipaddress
from http.cookies import SimpleCookie
from app.services.signature import (
    INFRA_SIGNATURES,
    SECURITY_HEADERS,
    TECH_SIGNATURES,
    WAF_SIGNATURES,
)

# --- CONFIGURATION ---
DNS_TIMEOUT = 3
TCP_TIMEOUT = 3
HTTP_TIMEOUT = 8
LIGHT_WAF_TIMEOUT = 4
UA_CHROME = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

try:
    from wafw00f.main import WafW00F
    WAFW00F_AVAILABLE = True
except ImportError:
    WAFW00F_AVAILABLE = False


# -------------------------------------------------------------------
# UTILS
# -------------------------------------------------------------------

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

def _identify_waf_passive(headers, cookies, body, dns_info):
    headers_lower = {k.lower(): str(v).lower() for k, v in headers.items()}
    cookie_names = [k.lower() for k in cookies.keys()]
    body_lower = body.lower() if body else ""

    dns_signals = dns_info.get("cname", []) + dns_info.get("ns", [])

    for provider, sigs in WAF_SIGNATURES.items():
        if any(h in headers_lower for h in sigs.get("headers", [])): return provider
        if any(c in cookie_names for c in sigs.get("cookies", [])): return provider
        if any(b in body_lower for b in sigs.get("body", [])): return provider
        if any(kw in signal for signal in dns_signals for kw in sigs.get("cname", [])): return provider

    ptr = dns_info.get("ptr", "")
    for provider, sigs in INFRA_SIGNATURES.items():
        if any(s in ptr for s in sigs.get("dns", [])): return sigs.get("waf")
        if any(s in signal for signal in dns_signals for s in sigs.get("dns", [])): return sigs.get("waf")

    return None


def _identify_waf_active_light(target_url):
    try:
        resp = requests.get(
            target_url + "/?id=1' OR '1'='1",
            headers=get_headers(),
            timeout=LIGHT_WAF_TIMEOUT,
            impersonate="chrome120",
        )
        if resp.status_code in (403, 406, 429, 501):
            return _identify_waf_passive(resp.headers, resp.cookies, resp.text, {})
    except requests.exceptions.RequestException:
        pass
    return None


# -------------------------------------------------------------------
# DNS
# -------------------------------------------------------------------

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

        res["cname"] = [_normalize_host(r) for r in _resolve_records(domain, "CNAME")]
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
        result["details"].append("-20 pts: Certificat invalide (Mismatch)")
    except ssl.SSLError:
        result["error_type"] = "ssl_invalid"
        result["details"].append("-20 pts: Certificat SSL invalide/expiré")
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
        "server": "Masqué", "waf": "Non détecté", "headers": {}, "missing": [], 
        "cookies": [], "details": [], "tech": [], "ssl_worked": False, "critical_failure": False
    }

    session = requests.Session()

    try:
        # 1. Test HTTPS Principal
        https_url = f"https://{domain}" if not target_url.startswith("https") else target_url
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
        else:
            res["critical_failure"] = True
            res["details"].append("-100 pts: Redirection DANGEREUSE vers HTTP")
            return res

        # 2. Test de redirection HTTP vers HTTPS (Enforce SSL)
        try:
            http_resp = session.get(
                f"http://{domain}",
                headers=get_headers(),
                timeout=LIGHT_WAF_TIMEOUT,
                allow_redirects=True,
                impersonate="chrome120",
            )
            if http_resp.status_code < 400 and http_resp.url.startswith("http://"):
                res["critical_failure"] = True
                res["details"].append("-100 pts: 🚨 HTTPS NON FORCÉ (Site accessible en clair)")
                return res 
        except requests.exceptions.RequestException:
            pass 

        # --- Analyse WAF (Hiérarchie de précision) ---
        waf_found = None
        
        # A. Priorité 1 : WafW00F (Détection Active Profonde)
        if WAFW00F_AVAILABLE:
            try:
                wf = WafW00F(https_url)
                ident = wf.identwaf(allwafs=False)
                if ident:
                    waf_found = str(ident[0])
                    res["details"].append(f"+15 pts: Détection active confirmée ({waf_found})")
            except:
                pass

        # B. Priorité 2 : Signatures Passives (Si WafW00F n'a rien vu)
        if not waf_found:
            waf_found = _identify_waf_passive(resp.headers, resp.cookies, resp.text, dns_info)

        # C. Priorité 3 : Analyse Active Légère (Dernier recours)
        if not waf_found:
            waf_found = _identify_waf_active_light(https_url)
        
        # Attribution du résultat WAF
        res["waf"] = waf_found or "Non détecté"
        if res["waf"] != "Non détecté" and not any("+15 pts" in d for d in res["details"]):
            res["details"].append(f"+15 pts: Protection WAF détectée ({res['waf']})")

        # --- Analyse Technologies et Headers ---
        res["server"] = resp.headers.get("Server", "Masqué")
        
        # Détection des technos
        raw_data = (res["server"] + " " + headers_lower.get("x-powered-by", "")).lower()
        for tech, sigs in TECH_SIGNATURES.items():
            if any(sig in raw_data for sig in sigs): 
                res["tech"].append(tech)

        # Analyse des Headers de sécurité
        for h_real, h_name in SECURITY_HEADERS.items():
            if h_real.lower() in headers_lower:
                res["headers"][h_name] = "✅ Présent"
                res["details"].append(f"+5 pts: {h_name}")
            else:
                res["headers"][h_name] = "❌ Manquant"
                res["missing"].append(h_name)
        if "HSTS" in res["missing"]:
            try:
                www_resp = session.get(f"https://www.{domain}", headers=get_headers(), 
                                       timeout=LIGHT_WAF_TIMEOUT, impersonate="chrome120")
                if "strict-transport-security" in {k.lower() for k in www_resp.headers}:
                    res["headers"]["HSTS"] = "✅ Présent (www)"
                    res["missing"].remove("HSTS")
                    res["details"].append("+5 pts: HSTS")
            except requests.exceptions.RequestException:
                pass

        # Audit des Cookies
        res["cookies"] = _audit_cookies(resp)

    # --- GESTION DES ERREURS ---
    except (requests.exceptions.SSLError, requests.exceptions.ProxyError):
        res["critical_failure"] = True
        res["details"].append("-100 pts: Échec connexion SSL (Certificat Invalide)")

    except requests.exceptions.ConnectionError:
        is_443_open = check_tcp_port(domain, 443)
        if is_443_open:
            try:
                # Vérification manuelle si le serveur bloque les requêtes HTTP (Forteresse)
                ctx = ssl.create_default_context()
                ctx.check_hostname = True 
                ctx.verify_mode = ssl.CERT_REQUIRED
                with socket.create_connection((domain, 443), timeout=LIGHT_WAF_TIMEOUT) as s:
                    with ctx.wrap_socket(s, server_hostname=domain) as ss:
                        res["waf"], res["server"] = "🏰 Forteresse", "Protégé"
                        res["details"].extend(["+30 pts: Filtrage Trafic Avancé", "+15 pts: Protection Périmétrique Active"])
                        for _, h in SECURITY_HEADERS.items(): 
                            res["headers"][h] = "🛡️ Masqué"
                        res["tech"].append("Firewall Avancé")
            except (ssl.SSLError, socket.timeout, OSError):
                res["critical_failure"] = True
                res["details"].append("-100 pts: Port 443 ouvert mais SSL invalide")
        else:
            res["details"].append("-50 pts: Site Inaccessible")

    except requests.exceptions.Timeout:
        res["details"].append("-10 pts: Timeout HTTP")
    except requests.exceptions.RequestException as e:
        res["details"].append(f"-10 pts: Erreur HTTP ({e})")

    return res

# -------------------------------------------------------------------
# MAIN ORCHESTRATOR
# -------------------------------------------------------------------

def is_safe_domain(ip: str) -> bool:
    return _is_public_ip(ip)

def analyze_target(domain):
    domain = domain.lower().strip()
    target_url = f"https://{domain}"

    dns_d = get_dns_info(domain)

    if dns_d.get("error"):
        return {"error": "NXDOMAIN", "domain": domain, "scan_data": {"numeric_score": 0}}

    if not _has_only_public_ips(dns_d):
        return {"error": "PRIVATE_IP", "domain": domain}

    # Imports tardifs : ces modules réutilisent DNS_TIMEOUT, _is_public_ip... d'ici.
    from app.services.dns_security import analyze_dns_security
    from app.services.tls_analysis import analyze_tls_deep

    with ThreadPoolExecutor(max_workers=4) as ex:
        f_ssl = ex.submit(get_ssl_info, domain)
        f_http = ex.submit(get_http_info, target_url, dns_d, domain)
        f_dns_sec = ex.submit(analyze_dns_security, domain)
        f_tls_deep = ex.submit(analyze_tls_deep, domain)
        ssl_d, http_d = f_ssl.result(), f_http.result()
        dns_sec = f_dns_sec.result()
        tls_deep = f_tls_deep.result()

    # KILL-SWITCH : Si critical_failure est activé, Score = 0
    if http_d.get("critical_failure"):
        return {
            "domain": domain, "ip": dns_d["ip"], 
            "ssl": {"valid": False, "issuer": "Non Sécurisé", "details": ssl_d["details"]}, 
            "waf_detected": "Non détecté", "server": "Non Sécurisé", 
            "headers": {}, "missing_headers": list(SECURITY_HEADERS.values()), 
            "cookies_security": [], "tech_stack": ["HTTP Non Forcé"], 
            "score_details": http_d["details"] + ["🚨 SCORE ANNULÉ"],
            "critical_failure": True,
        }

    # Inférence infra
    current_waf = http_d.get("waf", "Non détecté")

    # FIX FORTERESSE (Manquant dans ton code)
    if "Forteresse" in current_waf:
        ssl_d["valid"] = True
        ssl_d["issuer"] = "Protégé par Firewall"
        if "+20 pts: SSL opérationnel" not in ssl_d["details"]:
            ssl_d["details"].append("+20 pts: SSL Valide (Handshake OK)")

    # Rattrapage SSL Standard
    elif not ssl_d["valid"] and http_d["ssl_worked"] and not ssl_d.get("error_type") == "ssl_mismatch":
        ssl_d.update({"valid": True, "issuer": "Vérifié via HTTPS", "details": ["+20 pts: SSL opérationnel"]})

    # Inférence Infra
    issuer_str = str(ssl_d.get("issuer", "")).lower()
    ptr_str = str(dns_d.get("ptr", "")).lower()

    for provider, sigs in INFRA_SIGNATURES.items():
        ssl_match = any(s.lower() in issuer_str for s in sigs["issuers"])
        dns_match = any(s.lower() in ptr_str for s in sigs["dns"])
        
        if ssl_match or dns_match:
            if ssl_match: ssl_d["issuer"] = provider 
            if "Non détecté" in current_waf: current_waf = sigs["waf"]
            http_d["details"].append(f"+10 pts: Infrastructure {provider} détectée")
            break
            
    http_d["waf"] = current_waf

    unique_tech = list(dict.fromkeys(http_d["tech"]))
    if not unique_tech and "Inaccessible" not in http_d["waf"]: unique_tech = ["Obfusqué (Sécurisé)"]

    return {
        "domain": domain,
        "ip": dns_d["ip"],
        "ssl": ssl_d,
        "waf_detected": http_d["waf"],
        "server": http_d["server"],
        "headers": http_d["headers"],
        "missing_headers": http_d["missing"],
        "cookies_security": http_d.get("cookies", []),
        "tech_stack": unique_tech,
        "dns_security": {k: v for k, v in dns_sec.items() if k != "score_details"},
        "tls_deep": {k: v for k, v in tls_deep.items() if k != "details"},
        "score_details": (
            dns_d["details"] + ssl_d["details"] + http_d["details"]
            + dns_sec["score_details"] + tls_deep["details"]
        ),
    }
