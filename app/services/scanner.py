import requests
import ssl
import socket
import dns.resolver
import dns.reversename
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from fake_useragent import UserAgent  # Nouvelle librairie

# Configuration
TIMEOUT = 5
ua = UserAgent() # Initialisation du générateur d'User-Agent

# --- SIGNATURES (WAF & INFRA) ---
WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "__cfduid", "cf-cache-status", "cloudflare"],
    "Akamai": ["x-akamai", "akamai-origin-hop", "akamai", "x-akamai-request-id"],
    "Fastly": ["fastly", "x-fastly-request-id", "x-timer"],
    "Varnish": ["x-varnish", "varnish"],
    "AWS CloudFront": ["x-amz-cf-id", "cloudfront", "x-amz-id-2"],
    "Google Edge": ["gws", "esf", "sffe", "x-goog-"],
    "Imperva": ["incap-ses", "visid_incap", "x-iinfo", "x-cdn"],
    "Azure": ["x-azure-ref", "azure"],
    "F5 BIG-IP": ["bigip", "f5_cspm"],
    "Sucuri": ["x-sucuri", "sucuri"],
    "ModSecurity": ["mod_security", "nysobluewaf"],
    "DDOS-GUARD": ["ddos-guard"],
    "StackPath": ["x-stackpath"],
    "Zscaler": ["zscaler"]
}

INFRA_SIGNATURES = {
    "Google": {"issuers": ["Google Trust Services", "GTS CA"], "dns": ["google", "1e100.net"], "waf": "Google Edge"},
    "AWS": {"issuers": ["Amazon"], "dns": ["amazonaws", "cloudfront"], "waf": "AWS CloudFront"},
    "Microsoft": {"issuers": ["Microsoft"], "dns": ["azure", "trafficmanager"], "waf": "Azure Front Door"},
    "Cloudflare": {"issuers": ["Cloudflare"], "dns": ["cloudflare"], "waf": "Cloudflare"},
    "Vercel": {"issuers": ["Vercel", "Let's Encrypt"], "dns": ["vercel"], "waf": "Vercel Edge"},
    "Netlify": {"issuers": ["Netlify"], "dns": ["netlify"], "waf": "Netlify Edge"},
    "Heroku": {"issuers": ["Heroku"], "dns": ["herokuapp"], "waf": "Heroku Router"},
    "Shopify": {"issuers": ["Shopify"], "dns": ["shopify"], "waf": "Shopify Cloud"}
}

TECH_SIGNATURES = {
    "Nginx": ["nginx"], "Apache": ["apache"], "LiteSpeed": ["litespeed"],
    "Caddy": ["caddy"], "IIS": ["iis", "microsoft-iis"],
    "PHP": ["php", "phpsessid"], "ASP.NET": ["asp.net"],
    "Java": ["jsessionid", "tomcat", "jetty"], "Node.js": ["express", "node.js", "connect.sid"],
    "Python": ["gunicorn", "werkzeug", "python", "django", "flask"]
}

SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS",
    "Content-Security-Policy": "CSP",
    "X-Frame-Options": "Anti-Clickjacking",
    "X-Content-Type-Options": "Anti-Mime",
    "Referrer-Policy": "Referrer",
    "Permissions-Policy": "Permissions"
}

def get_random_headers():
    """Génère des headers pour ressembler à un vrai navigateur"""
    return {
        "User-Agent": ua.random,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    }

def check_tcp_port(domain, port=443):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((domain, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def get_dns_info(domain):
    res = {"ip": "Inconnue", "ptr": "", "details": [], "error": False}
    try:
        answers = dns.resolver.resolve(domain, 'A')
        ip = answers[0].to_text()
        res["ip"] = ip
        try:
            rev_name = dns.reversename.from_address(ip)
            ptr_answers = dns.resolver.resolve(rev_name, "PTR")
            res["ptr"] = ptr_answers[0].to_text().lower()
        except Exception:
            pass # Pas de PTR, ce n'est pas critique
    except dns.resolver.NXDOMAIN:
        res["details"].append("-100 pts: Domaine inexistant (NXDOMAIN)")
        res["error"] = True
    except Exception as e:
        res["details"].append(f"-10 pts: Erreur DNS ({str(e)})")
        # On ne met pas error=True ici pour tenter quand même le HTTP via le domaine
    
    return res

def get_ssl_info(domain):
    result = {"valid": False, "issuer": "Inconnu", "expiry": "N/A", "details": []}
    
    # Pré-check TCP
    if not check_tcp_port(domain, 443):
        result["details"].append("-20 pts: Port 443 Fermé (Pas de HTTPS)")
        return result

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False # On gère l'erreur manuellement pour avoir plus de détails
        ctx.verify_mode = ssl.CERT_NONE # Idem, on veut juste lire le cert
        
        # Connexion sécurisée avec timeout court
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=False) # Si CERT_NONE, getpeercert retourne rien souvent, il faut ajuster
                
                # Pour récupérer les infos proprement, on doit souvent valider.
                # Nouvelle approche plus robuste :
                pass
        
        # Approche standard "safe"
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                issuer = dict(x[0] for x in cert['issuer'])
                common = issuer.get('commonName', '')
                org = issuer.get('organizationName', '')
                final_name = org if org else common
                
                result["valid"] = True
                result["issuer"] = final_name if final_name else "Inconnu"
                result["expiry"] = cert['notAfter']
                result["details"].append("+20 pts: Certificat SSL Valide")
                
                # Bonus pour les gros CA
                if any(x in str(final_name) for x in ["DigiCert", "GlobalSign", "Entrust", "Amazon", "Google", "Let's Encrypt"]):
                    result["details"].append("+5 pts: Autorité de Certification Reconnue")

    except ssl.SSLError:
        result["error"] = "Certificat Invalide"
        result["details"].append("-20 pts: Certificat SSL Invalide ou Expiré")
    except socket.timeout:
        result["valid"] = True 
        result["issuer"] = "Inconnu (Timeout)"
        result["details"].append("+10 pts: SSL lent ou filtré (Timeout)")
    except Exception as e:
        result["error"] = str(e)
        result["details"].append("-10 pts: Erreur Handshake SSL")
    return result

def get_http_info(target_url, domain):
    res = {
        "server": "Masqué", "waf": "Non détecté", "headers": {}, 
        "missing": [], "cookies": [], "details": [], "tech": []
    }
    
    session = requests.Session()
    retry = Retry(total=2, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('https://', adapter)
    session.mount('http://', adapter)

    try:
        # 1. Vérification redirection HTTP -> HTTPS
        try:
            r_red = requests.get(f"http://{domain}", headers=get_random_headers(), timeout=3, allow_redirects=False)
            if r_red.status_code in [301, 302, 308] and "https://" in r_red.headers.get('Location', ''):
                res["details"].append("+5 pts: Force HTTPS (Redirection OK)")
            elif r_red.status_code == 200:
                 res["details"].append("-10 pts: HTTP accessible sans redirection")
                 res["tech"].append("HTTP Allowed")
        except Exception:
            pass

        # 2. Requête principale
        resp = session.get(target_url, headers=get_random_headers(), timeout=TIMEOUT, allow_redirects=True)
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        res["server"] = resp.headers.get("Server", "Masqué")
        
        # Analyse Technologies
        raw_data = (res["server"] + " " + headers_lower.get("x-powered-by", "")).lower()
        for tech, sigs in TECH_SIGNATURES.items():
            if any(sig in raw_data for sig in sigs) and tech not in res["tech"]:
                res["tech"].append(tech)

        # Détection WAF (Headers + Cookies + Contenu erreur)
        waf_signals = []
        is_blocked = resp.status_code in [403, 406, 429]
        
        if is_blocked:
            res["details"].append("+20 pts: Comportement WAF détecté (Blocage)")
        
        for waf, sigs in WAF_SIGNATURES.items():
            # Check Headers
            if any(sig in h for h in headers_lower for sig in sigs):
                waf_signals.append(waf)
                continue
            # Check Cookies (parfois les cookies trahissent le WAF)
            for cookie in resp.cookies:
                if any(sig in cookie.name.lower() for sig in sigs):
                    waf_signals.append(waf)

        if waf_signals:
            res["waf"] = ", ".join(list(set(waf_signals)))
            if not is_blocked: res["details"].append(f"+10 pts: Signature WAF trouvée ({res['waf']})")

        # Analyse Cookies
        if resp.cookies:
            for c in resp.cookies:
                issues = []
                is_csrf = any(x in c.name.lower() for x in ["csrf", "xsrf", "token"])
                if not c.secure: issues.append("Manque Secure")
                if not c.has_nonstandard_attr('HttpOnly') and not is_csrf: issues.append("Manque HttpOnly")
                
                if issues: res["cookies"].append(f"{c.name}: ❌ {', '.join(issues)}")
                else: res["cookies"].append(f"{c.name}: ✅ OK")
        else:
            res["cookies"].append("Aucun cookie")

        # Analyse Headers de Sécurité
        for h_real, h_name in SECURITY_HEADERS.items():
            if h_real.lower() in headers_lower:
                res["headers"][h_name] = "✅ Présent"
                res["details"].append(f"+5 pts: {h_name}")
            else:
                res["headers"][h_name] = "❌ Manquant"
                res["missing"].append(h_name)
                res["details"].append(f"-5 pts: {h_name} manquant")

    except requests.exceptions.SSLError:
        res["details"].append("-20 pts: Erreur SSL critique lors de la connexion")
    except requests.exceptions.ConnectionError:
        res["details"].append("-50 pts: Site inaccessible ou connexion refusée")
    except Exception as e:
        res["details"].append(f"-10 pts: Erreur analyse HTTP ({str(e)})")

    return res

def analyze_target(domain):
    """
    Orchestrateur Principal
    """
    if not domain.startswith('http'):
        target_url = f"https://{domain}"
    else:
        target_url = domain
        domain = urlparse(target_url).netloc

    # Exécution parallèle
    with ThreadPoolExecutor(max_workers=3) as executor:
        f_dns = executor.submit(get_dns_info, domain)
        f_ssl = executor.submit(get_ssl_info, domain)
        f_http = executor.submit(get_http_info, target_url, domain)

        dns_d = f_dns.result()
        ssl_d = f_ssl.result()
        http_d = f_http.result()

    # Si DNS échoue totalement, on arrête
    if dns_d.get("error"):
        return {
            "domain": domain, "ip": "N/A", "ssl": {"valid": False}, 
            "waf_detected": "Inconnu", "headers": {}, "cookies_security": [], 
            "tech_stack": [], "score_details": dns_d["details"], 
            "missing_headers": [], "scan_data": {"numeric_score": 0}
        }

    # Inférence Infrastructure (si le WAF n'est pas détecté par headers)
    current_waf = http_d.get("waf", "Non détecté")
    if "Non détecté" in current_waf:
        issuer = str(ssl_d.get("issuer", ""))
        ptr = str(dns_d.get("ptr", ""))
        
        for provider, sigs in INFRA_SIGNATURES.items():
            is_ssl = any(s.lower() in issuer.lower() for s in sigs["issuers"])
            is_dns = any(s.lower() in ptr.lower() for s in sigs["dns"])
            
            if is_ssl or is_dns:
                current_waf = f"{sigs['waf']} (Inféré)"
                http_d["details"].append(f"+10 pts: Infrastructure {provider} détectée")
                break
        http_d["waf"] = current_waf

    return {
        "domain": domain,
        "ip": dns_d["ip"],
        "ssl": ssl_d,
        "waf_detected": http_d["waf"],
        "server": http_d["server"],
        "headers": http_d["headers"],
        "missing_headers": http_d["missing"],
        "cookies_security": http_d["cookies"],
        "tech_stack": list(set(http_d["tech"])),
        "score_details": dns_d["details"] + ssl_d["details"] + http_d["details"]
    }