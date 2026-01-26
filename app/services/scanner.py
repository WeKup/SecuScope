import requests
import ssl
import socket
import dns.resolver
import dns.reversename
import re
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


TIMEOUT = 5
UA_CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "__cfduid", "cf-cache-status", "cloudflare"],
    "Akamai": ["x-akamai", "akamai-origin-hop", "akamai", "x-akamai-request-id"],
    "Fastly": ["fastly", "x-fastly-request-id", "x-timer"],
    "Varnish": ["x-varnish", "varnish"],
    "AWS CloudFront": ["x-amz-cf-id", "cloudfront", "x-amz-id-2"],
    "Google Edge": ["gws", "esf", "sffe", "x-goog-"],
    "Facebook Proxygen": ["proxygen", "x-fb-debug"],
    "Imperva": ["incap-ses", "visid_incap", "x-iinfo", "x-cdn"],
    "Sucuri": ["x-sucuri", "sucuri"],
    "Azure": ["x-azure-ref", "azure"],
    "F5 BIG-IP": ["bigip", "f5_cspm"],
    "Barracuda": ["barra_counter_session", "bnjb"],
    "Citrix": ["ns_af", "citrix_ns_id"],
    "ArvanCloud": ["arvancloud"],
    "Reblaze": ["x-reblaze"],
    "ModSecurity": ["mod_security", "nysobluewaf"],
    "StackPath": ["x-stackpath"],
    "Zscaler": ["zscaler"],
    "Fortinet": ["fortiwaf"],
    "Oracle Cloud": ["oracle", "x-oracle-dms"]
}

INFRA_SIGNATURES = {
    "Google": {
        "issuers": ["Google Trust Services", "GTS CA"],
        "dns": ["1e100.net", "googleusercontent.com", "google.com", "bc.googleusercontent.com"],
        "waf": "Google Edge / GWS",
        "tech": "Google Server"
    },
    "AWS": {
        "issuers": ["Amazon"],
        "dns": ["cloudfront.net", "awsglobalaccelerator.com", "amazonaws.com", "compute.amazonaws.com"],
        "waf": "AWS CloudFront",
        "tech": "AWS Infrastructure"
    },
    "Microsoft Azure": {
        "issuers": ["Microsoft Corporation", "Microsoft Azure"],
        "dns": ["azure.com", "azure-dns.com", "trafficmanager.net", "azureedge.net"],
        "waf": "Azure Front Door",
        "tech": "Azure Cloud"
    },
    "Oracle Cloud": {
        "issuers": ["Oracle Corporation", "DigiCert Global Root G2"],
        "dns": ["oraclecloud.com", "oracle.com", "oci.oraclecloud.com"],
        "waf": "Oracle OCI WAF",
        "tech": "Oracle Infrastructure"
    },
    "Cloudflare": {
        "issuers": ["Cloudflare"],
        "dns": ["cloudflare.com"], 
        "waf": "Cloudflare",
        "tech": "Cloudflare CDN"
    },
    "Fastly": {
        "issuers": ["Fastly"],
        "dns": ["fastly.net", "fastlylb.net"],
        "waf": "Fastly Edge",
        "tech": "Varnish Cache"
    },
    "Akamai": {
        "issuers": ["Akamai"],
        "dns": ["akamaitechnologies.com", "akamai.net", "akamaiedge.net"],
        "waf": "Akamai Edge",
        "tech": "Akamai CDN"
    },
    "Vercel": {
        "issuers": ["Vercel"],
        "dns": ["vercel.com", "vercel-dns.com"],
        "waf": "Vercel Edge",
        "tech": "Next.js / Vercel"
    },
    "Netlify": {
        "issuers": ["Netlify"],
        "dns": ["netlify.com"],
        "waf": "Netlify Edge",
        "tech": "Netlify"
    },
    "Heroku": {
        "issuers": ["Heroku"],
        "dns": ["herokuapp.com"],
        "waf": "Heroku Router",
        "tech": "Heroku Dyno"
    },
    "Shopify": {
        "issuers": ["Shopify"],
        "dns": ["myshopify.com", "shopify.com"],
        "waf": "Shopify Cloud",
        "tech": "Ruby on Rails (Shopify)"
    },
    "DigitalOcean": {
        "issuers": ["DigitalOcean"],
        "dns": ["digitalocean.com"],
        "waf": "DigitalOcean Load Balancer",
        "tech": "DigitalOcean Droplet"
    },
    "Alibaba Cloud": {
        "issuers": ["Alibaba", "GlobalSign"],
        "dns": ["alicdn.com", "kunlun"],
        "waf": "Alibaba WAF",
        "tech": "Alibaba Cloud"
    },
    "IBM Cloud": {
        "issuers": ["DigiCert"], 
        "dns": ["softlayer.com", "bluemix.net"],
        "waf": "IBM CIS",
        "tech": "IBM Cloud"
    }
}


TECH_SIGNATURES = {
    "Nginx": ["nginx"],
    "Apache": ["apache"],
    "LiteSpeed": ["litespeed"],
    "Caddy": ["caddy"],
    "IIS": ["iis", "microsoft-iis"],
    "PHP": ["php", "phpsessid"],
    "ASP.NET": ["asp.net", "asp.net_sessionid", "x-aspnet-version"],
    "Java": ["jsessionid", "tomcat", "jetty", "jboss"],
    "Node.js": ["express", "connect.sid", "node.js"],
    "Python": ["gunicorn", "werkzeug", "python", "django", "flask"],
    "Ruby": ["passenger", "thin", "mongrel", "ruby"]
}


SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS",
    "Content-Security-Policy": "CSP",
    "X-Frame-Options": "Anti-Clickjacking",
    "X-Content-Type-Options": "Anti-Mime",
    "Referrer-Policy": "Referrer",
    "Permissions-Policy": "Permissions"
}



def check_tcp_port(domain, port=443):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((domain, port))
        sock.close()
        return result == 0
    except:
        return False

def get_dns_info(domain):
    res = {"ip": "Inconnue", "ptr": "", "details": [], "error": False}
    try:
        answers = dns.resolver.resolve(domain, 'A')
        ip = answers[0].to_text()
        res["ip"] = ip
        
        # PTR Check (Reverse DNS)
        try:
            rev_name = dns.reversename.from_address(ip)
            ptr_answers = dns.resolver.resolve(rev_name, "PTR")
            res["ptr"] = ptr_answers[0].to_text().lower()
        except:
            pass

    except dns.resolver.NXDOMAIN:
        res["details"].append("-100 pts: Domaine inexistant (NXDOMAIN)")
        res["error"] = True
    except dns.resolver.NoAnswer:
        res["details"].append("-10 pts: Pas d'enregistrement A (DNS Privé ?)")
    except Exception as e:
        pass
    
    return res

def get_ssl_info(domain):
    result = {"valid": False, "issuer": "Inconnu", "expiry": "N/A", "details": []}
    
    if not check_tcp_port(domain, 443):
        result["details"].append("-20 pts: Port 443 Fermé (Pas de HTTPS)")
        return result

    try:
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
                
                if any(x in str(final_name) for x in ["DigiCert", "GlobalSign", "Entrust", "Sectigo", "Amazon", "Google"]):
                    result["details"].append("+5 pts: Autorité de Certification Reconnue")

    except ssl.SSLError:
        result["error"] = "Certificat Invalide"
        result["details"].append("-20 pts: Certificat SSL Invalide")
    except socket.timeout:
        result["valid"] = True 
        result["issuer"] = "Masqué par WAF"
        result["details"].append("+20 pts: Handshake SSL Filtré (Protection Active)")
    except Exception as e:
        result["error"] = str(e)
        result["details"].append("-10 pts: Erreur Connexion SSL")
    return result

def get_http_info(target_url, domain):
    res = {
        "server": "Masqué", "waf": "Non détecté", "headers": {}, 
        "missing": [], "cookies": [], "details": [], "tech": []
    }
    
    session = requests.Session()
    retry = Retry(total=2, backoff_factor=0.5)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('https://', adapter)
    session.mount('http://', adapter)

    try:
        # Redirect Check
        try:
            r_red = requests.get(f"http://{domain}", headers={"User-Agent": UA_CHROME}, timeout=3, allow_redirects=False)
            if r_red.status_code in [301, 302, 307, 308] and r_red.headers.get('Location', '').startswith('https://'):
                res["details"].append("+5 pts: Force HTTPS (Redirection OK)")
            elif r_red.status_code == 200:
                 res["details"].append("-10 pts: HTTPS non forcé")
                 res["tech"].append("HTTP Allowed")
        except: pass

        # Main Request
        resp = session.get(target_url, headers={"User-Agent": UA_CHROME}, timeout=TIMEOUT, allow_redirects=True)
        final_headers = {k.lower(): v for k, v in resp.headers.items()}
        res["server"] = resp.headers.get("Server", "Masqué")
        
        # Tech Analysis (Headers)
        raw_data = (res["server"] + " " + final_headers.get("x-powered-by", "") + " " + " ".join([c.name for c in resp.cookies])).lower()
        for tech, sigs in TECH_SIGNATURES.items():
            for sig in sigs:
                if sig in raw_data and tech not in res["tech"]: res["tech"].append(tech)

        # WAF Detection (Headers)
        waf_signals = []
        blocked = False
        if resp.status_code in [403, 406, 429, 503]:
            txt = resp.text.lower()
            if "captcha" in txt or "security" in txt or "forbidden" in txt:
                waf_signals.append("🛡️ Protection Active")
                res["details"].append("+20 pts: WAF Bloquant")
                blocked = True

        via = final_headers.get("via", "").lower()
        for waf, sigs in WAF_SIGNATURES.items():
            for sig in sigs:
                if any(sig in h for h in final_headers) or sig in raw_data or sig in via:
                    waf_signals.append(waf)
                    break
        
        if waf_signals:
            res["waf"] = ", ".join(list(set(waf_signals)))
            if not blocked: res["details"].append(f"+10 pts: Infrastructure WAF détectée")

        # Cookies
        if resp.cookies:
            for c in resp.cookies:
                issues = []
                is_csrf = any(x in c.name.lower() for x in ["csrf", "xsrf", "token", "id"])
                if not c.secure: issues.append("Manque Secure")
                if not c.has_nonstandard_attr('HttpOnly') and not is_csrf: issues.append("Manque HttpOnly")
                if issues: res["cookies"].append(f"{c.name}: ❌ {', '.join(issues)}")
                else: res["cookies"].append(f"{c.name}: ✅ Sécurisé")
        else: res["cookies"].append("Pas de cookies")

        # Headers
        for h_real, h_name in SECURITY_HEADERS.items():
            if h_real.lower() in final_headers:
                res["headers"][h_name] = "✅ Présent"
                res["details"].append(f"+5 pts: {h_name}")
            else:
                if blocked: res["headers"][h_name] = "🔒 WAF Géré"
                else:
                    res["headers"][h_name] = "❌ Manquant"
                    res["missing"].append(h_name)
                    res["details"].append(f"-5 pts: {h_name} manquant")

    except:
        # Fallback Analysis
        is_443 = check_tcp_port(domain, 443)
        http_ok = False
        try:
            if requests.get(f"http://{domain}", timeout=3).status_code < 500: http_ok = True
        except: pass

        if http_ok:
            res["waf"], res["server"] = "N/A", "Non Sécurisé"
            res["details"].extend(["-100 pts: DANGER - Site HTTP Only", "-20 pts: Données en clair"])
            for _, h in SECURITY_HEADERS.items(): res["headers"][h] = "⚠️ Non Chiffré"
            res["cookies"].append("Non Chiffrés")
            res["tech"].append("HTTP Legacy")
        elif is_443:
            res["waf"], res["server"] = "🏰 Forteresse", "Protégé"
            res["details"].extend(["+30 pts: Filtrage Trafic", "+10 pts: Site Furtif"])
            for _, h in SECURITY_HEADERS.items(): res["headers"][h] = "🛡️ Masqué"
            res["cookies"].append("Protégé")
            res["tech"].append("Firewall Avancé")
        else:
            res["waf"] = "N/A"
            res["details"].append("-50 pts: Site Inaccessible")
            for _, h in SECURITY_HEADERS.items(): res["headers"][h] = "⚠️ Down"

    return res

def analyze_target(domain):
    """
    Orchestrateur avec Inférence Infrastructure Générique (V5)
    """
    if not domain.startswith('http'):
        target_url = f"https://{domain}"
    else:
        target_url = domain
        domain = urlparse(target_url).netloc

    with ThreadPoolExecutor(max_workers=3) as executor:
        f_dns = executor.submit(get_dns_info, domain)
        f_ssl = executor.submit(get_ssl_info, domain)
        f_http = executor.submit(get_http_info, target_url, domain)

        dns_d = f_dns.result()
        ssl_d = f_ssl.result()
        http_d = f_http.result()

    if dns_d.get("error"):
        return {"scan_data": {"numeric_score": 0}, "error": "Domaine introuvable", "domain": domain, "ip": "N/A", "ssl": {"valid": False}, "waf_detected": "N/A", "headers": {}, "cookies_security": [], "tech_stack": [], "score_details": [], "missing_headers": []}

    
    current_waf = http_d.get("waf", "Non détecté")
    
    if "Non détecté" in current_waf:
        issuer = str(ssl_d.get("issuer", ""))
        ptr = str(dns_d.get("ptr", ""))
        
        
        for provider, sigs in INFRA_SIGNATURES.items():
            
            
            ssl_match = any(s.lower() in issuer.lower() for s in sigs["issuers"])
            
            
            dns_match = any(s.lower() in ptr.lower() for s in sigs["dns"])
            
            if ssl_match or dns_match:
                current_waf = sigs["waf"]
                source = "SSL" if ssl_match else "DNS"
                http_d["details"].append(f"+10 pts: Infrastructure {provider} détectée ({source})")
                
                
                if "tech" in sigs and sigs["tech"] not in http_d["tech"]:
                    http_d["tech"].append(sigs["tech"])
                    
                break 

        http_d["waf"] = current_waf

    
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
        "cookies_security": http_d["cookies"],
        "tech_stack": unique_tech,
        "score_details": dns_d["details"] + ssl_d["details"] + http_d["details"]
    }