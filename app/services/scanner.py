import requests
import ssl
import socket
import dns.resolver
import dns.reversename
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from app.services.signature import *

# --- CONFIGURATION ---
TIMEOUT = 10
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
            s.settimeout(3)
            return s.connect_ex((domain, port)) == 0
    except Exception:
        return False


# -------------------------------------------------------------------
# WAF DETECTION
# -------------------------------------------------------------------

def _identify_waf_passive(headers, cookies, body, dns_info):
    headers_lower = {k.lower(): str(v).lower() for k, v in headers.items()}
    cookie_names = [c.name.lower() for c in cookies]
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
        resp = requests.get(target_url + "/?id=1' OR '1'='1", headers=get_headers(), timeout=5)
        if resp.status_code in (403, 406, 429, 501):
            return _identify_waf_passive(resp.headers, resp.cookies, resp.text, {})
    except Exception:
        pass
    return None


# -------------------------------------------------------------------
# DNS
# -------------------------------------------------------------------

def get_dns_info(domain):
    res = {"ip": "Inconnue", "ptr": "", "cname": [], "ns": [], "details": [], "error": False}
    try:
        answers = dns.resolver.resolve(domain, "A")
        res["ip"] = answers[0].to_text()
        try:
            rev = dns.reversename.from_address(res["ip"])
            res["ptr"] = str(dns.resolver.resolve(rev, "PTR")[0]).lower()
        except: pass
        try:
            res["cname"] = [str(r.target).lower().rstrip(".") for r in dns.resolver.resolve(domain, "CNAME")]
        except: pass
        try:
            res["ns"] = [str(r.target).lower().rstrip(".") for r in dns.resolver.resolve(domain, "NS")]
        except: pass
    except dns.resolver.NXDOMAIN:
        res["details"].append("Domaine inexistant (NXDOMAIN)")
        res["error"] = True
    except Exception as e:
        if "timeout" in str(e).lower(): res["error"] = True
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

        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
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
    except Exception:
        result["error_type"] = "connection_error"

    return result


# -------------------------------------------------------------------
# HTTP (V12 - Avec Check HTTPS Forcé)
# -------------------------------------------------------------------

def get_http_info(target_url, dns_info, domain):
    res = {
        "server": "Masqué", "waf": "Non détecté", "headers": {}, "missing": [], 
        "cookies": [], "details": [], "tech": [], "ssl_worked": False, "critical_failure": False
    }

    session = requests.Session()
    session.mount("https://", HTTPAdapter(max_retries=Retry(total=2, backoff_factor=0.5)))
    session.mount("http://", HTTPAdapter(max_retries=Retry(total=2, backoff_factor=0.5)))

    try:
        # 1. Test HTTPS Principal
        https_url = f"https://{domain}" if not target_url.startswith("https") else target_url
        resp = session.get(https_url, headers=get_headers(), timeout=TIMEOUT, allow_redirects=True)

        # Vérification redirection inverse (HTTPS -> HTTP)
        if resp.url.startswith("https://"):
            res["ssl_worked"] = True
        else:
            res["critical_failure"] = True
            res["details"].append("-100 pts: Redirection DANGEREUSE vers HTTP")
            return res

        # 2. Test de redirection HTTP vers HTTPS (Enforce SSL)
        try:
            http_resp = session.get(f"http://{domain}", headers=get_headers(), timeout=5, allow_redirects=True)
            if http_resp.status_code < 400 and http_resp.url.startswith("http://"):
                res["critical_failure"] = True
                res["details"].append("-100 pts: 🚨 HTTPS NON FORCÉ (Site accessible en clair)")
                return res 
        except:
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
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
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

        # Audit des Cookies
        if resp.cookies:
            for c in resp.cookies: 
                res["cookies"].append(f"{c.name}: {'✅ OK' if c.secure else '❌ Insecure'}")
        else:
            res["cookies"].append("Aucun cookie")

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
                with socket.create_connection((domain, 443), timeout=5) as s:
                    with ctx.wrap_socket(s, server_hostname=domain) as ss:
                        res["waf"], res["server"] = "🏰 Forteresse", "Protégé"
                        res["details"].extend(["+30 pts: Filtrage Trafic Avancé", "+15 pts: Protection Périmétrique Active"])
                        for _, h in SECURITY_HEADERS.items(): 
                            res["headers"][h] = "🛡️ Masqué"
                        res["tech"].append("Firewall Avancé")
            except:
                res["critical_failure"] = True
                res["details"].append("-100 pts: Port 443 ouvert mais SSL invalide")
        else:
            res["details"].append("-50 pts: Site Inaccessible")

    except Exception as e:
        res["details"].append(f"-10 pts: Erreur HTTP ({e})")

    return res

# -------------------------------------------------------------------
# MAIN ORCHESTRATOR
# -------------------------------------------------------------------

def analyze_target(domain):
    domain = domain.lower().strip()
    target_url = f"https://{domain}"

    dns_d = get_dns_info(domain)
    if dns_d.get("error"):
        return {"error": "NXDOMAIN", "domain": domain, "scan_data": {"numeric_score": 0}}

    with ThreadPoolExecutor(max_workers=2) as ex:
        f_ssl = ex.submit(get_ssl_info, domain)
        f_http = ex.submit(get_http_info, target_url, dns_d, domain)
        ssl_d, http_d = f_ssl.result(), f_http.result()

    # KILL-SWITCH : Si critical_failure est activé, Score = 0
    if http_d.get("critical_failure"):
        return {
            "domain": domain, "ip": dns_d["ip"], 
            "ssl": {"valid": False, "issuer": "Non Sécurisé", "details": ssl_d["details"]}, 
            "waf_detected": "Non détecté", "server": "Non Sécurisé", 
            "headers": {}, "missing_headers": list(SECURITY_HEADERS.values()), 
            "cookies_security": [], "tech_stack": ["HTTP Non Forcé"], 
            "score_details": http_d["details"] + ["🚨 SCORE ANNULÉ"]
        }

    # Inférence & Bonus
    infrastructure_detected = False
    premium_provider = None
    current_waf = http_d.get("waf", "Non détecté")

    # FIX FORTERESSE (Manquant dans ton code)
    if "Forteresse" in current_waf:
        ssl_d["valid"] = True
        ssl_d["issuer"] = "Protégé par Firewall"
        infrastructure_detected = True
        premium_provider = "Firewall Haut Niveau"
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
            infrastructure_detected = True
            premium_provider = provider
            if ssl_match: ssl_d["issuer"] = provider 
            if "Non détecté" in current_waf: current_waf = sigs["waf"]
            http_d["details"].append(f"+10 pts: Infrastructure {provider} détectée")
            break
            
    http_d["waf"] = current_waf

    # Bonus Géants
    premium_list = ["Google", "Amazon", "Akamai", "Cloudflare", "Microsoft", "Firewall", "Firewall Haut Niveau"]
    if infrastructure_detected and ssl_d["valid"] and any(p in str(premium_provider) for p in premium_list):
        http_d["details"].append(f"+20 pts: Sécurité gérée par {premium_provider}")
        if http_d["missing"]:
            http_d["missing"] = []
            for h in list(http_d["headers"].keys()):
                if "Manquant" in str(http_d["headers"][h]): http_d["headers"][h] = "🛡️ Géré par Infra"

    unique_tech = list(set(http_d["tech"]))
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
        "score_details": dns_d["details"] + ssl_d["details"] + http_d["details"]
    }