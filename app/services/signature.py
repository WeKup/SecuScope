# Le scanner cherchera si ces mots-clés sont contenus (substring) dans :
# 1. Les Headers
# 2. Les Cookies
# 3. Le CNAME (Alias DNS)
# 4. Le NS (Serveur de nom)
WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "__cfduid", "cf-cache-status", "cloudflare", "cf-request-id"],
        "body": ["cloudflare ray id", "cloudflare-nginx", "v4-via"],
        "cookies": ["__cf_bm", "__cfduid", "_cfuvid"],
        "cname": ["cloudflare"]
    },
    "Akamai": {
        "headers": ["x-akamai", "akamai-origin-hop", "x-akamai-request-id", "akamai"],
        "body": ["akamaighost"],
        "cookies": ["ak_bmsc", "akamai"],
        "cname": ["akamai", "edgekey", "edgesuite", "akamaiedge"]
    },
    "Fastly": {
        "headers": ["fastly", "x-fastly-request-id", "x-timer"],
        "body": ["fastly"],
        "cookies": ["_fastly_session"],
        "cname": ["fastly"]
    },
    "Varnish": {
        "headers": ["x-varnish", "varnish"],
        "body": ["varnish"],
        "cookies": [],
        "cname": [] 
    },
    "AWS CloudFront": {
        "headers": ["x-amz-cf-id", "x-amz-cf-pop", "x-amz-id-2", "cloudfront"],
        "body": ["cloudfront"],
        "cookies": [],
        "cname": ["cloudfront", "awsglobalaccelerator"]
    },
    "Google Edge": {
        "headers": ["gws", "esf", "sffe", "x-goog-", "x-guploader-uploadid"],
        "body": ["google"],
        "cookies": [],
        "cname": ["googleusercontent", "1e100", "googlehosted"]
    },
    "Imperva / Incapsula": {
        "headers": ["x-iinfo", "x-cdn", "x-incap-sess", "incap_ses", "visid_incap"],
        "body": ["incapsula incident id", "powered by incapsula"],
        "cookies": ["visid_incap", "incap_ses"],
        "cname": ["incapdns", "impervadns"]
    },
    "Azure Front Door": {
        "headers": ["x-azure-ref", "x-fd-features", "azure"],
        "body": ["azure"],
        "cookies": [],
        "cname": ["azurefd", "azureedge", "trafficmanager"]
    },
    "F5 BIG-IP / Distributed Cloud": {
        "headers": ["x-wa-info", "x-cshm", "bigip", "f5_cspm"],
        "body": ["f5_cspm"],
        "cookies": ["mrhint", "f5_cspm"],
        "cname": ["f5edge", "silverline"]
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache", "sucuri"],
        "body": ["sucuri cloudproxy", "access denied - sucuri website firewall"],
        "cookies": ["sucuri_cloudproxy_uuid"],
        "cname": ["sucuri"]
    },
    "ModSecurity": {
        "headers": ["mod_security", "nysobluewaf"],
        "body": ["mod_security"],
        "cookies": [],
        "cname": []
    },
    "DDOS-GUARD": {
        "headers": ["ddos-guard"],
        "body": ["ddos-guard"],
        "cookies": [],
        "cname": ["ddos-guard"]
    },
    "StackPath": {
        "headers": ["x-stackpath"],
        "body": ["stackpath"],
        "cookies": [],
        "cname": ["stackpath"]
    },
    "Zscaler": {
        "headers": ["zscaler"],
        "body": ["zscaler"],
        "cookies": ["zscaler"],
        "cname": ["zscaler", "zen.zscaler", "zpa", "zscloud"]
    }
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