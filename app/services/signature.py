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