"""Catalogues de traduction (voir app/i18n.py).

FR       : texte source anglais (templates, routes) -> français.
STORED_EN: libellés stockés en français par scanner.py / scoring.py -> anglais, pour l'affichage.
           Les valeurs stockées ne changent jamais (anciens audits compris), seul l'affichage est traduit.
"""
import re

FR = {
    # --- base.html
    "external security audit": "audit de sécurité externe",
    "SecuScope, new scan": "SecuScope, nouveau scan",
    "Language": "Langue",
    "Personal Gemini key": "Clé Gemini personnelle",
    "Server Gemini key": "Clé Gemini du serveur",
    "AI model:": "Modèle IA :",
    "New scan": "Nouveau scan",
    "Log out": "Déconnexion",
    "Close message": "Fermer le message",
    "non-intrusive external audit, light active fingerprinting · privacy-respecting":
        "audit externe non intrusif, fingerprinting actif léger · respect de la vie privée",
    # --- login.html
    "Sign in": "Connexion",
    "Restricted access. The AI report is generated automatically, no key is required.":
        "Accès réservé. Le rapport IA est généré automatiquement, il n'y a aucune clé à renseigner.",
    "Email address": "Adresse e-mail",
    "Password": "Mot de passe",
    "Use my own Gemini key (optional)": "Utiliser ma propre clé Gemini (optionnel)",
    "AI model": "Modèle IA",
    "recommended": "recommandé",
    "keys created before ~end of July 2026, otherwise 404 error": "clés créées avant ~fin juillet 2026, sinon erreur 404",
    "Google Gemini API key": "Clé API Google Gemini",
    "Without a personal key, the server key is used. Yours stays in session memory and is never stored.":
        "Sans clé personnelle, la clé du serveur est utilisée. La vôtre reste en mémoire de session et n'est jamais enregistrée.",
    # --- index.html
    "Audit the security posture of a domain.": "Auditez la posture de sécurité d'un domaine.",
    "TLS, HTTP headers, DNS, cookies and WAF/CDN protections, scored out of 100. Non-intrusive external audit: no exploitation, only what the domain publicly exposes.":
        "TLS, en-têtes HTTP, DNS, cookies et protections WAF/CDN, notés sur 100. Audit externe non intrusif : aucune exploitation, seulement ce que le domaine expose publiquement.",
    "Domain to audit": "Domaine à auditer",
    "Audit domain": "Auditer le domaine",
    "I certify that I own this domain or have written authorization to run this external security audit.":
        "Je certifie être propriétaire de ce domaine ou disposer d'une autorisation écrite pour effectuer cet audit de sécurité externe.",
    "Seal awaiting verdict": "Sceau en attente de verdict",
    "PENDING": "EN ATTENTE",
    "Audit in progress": "Audit en cours",
    "0.0 s": "0,0 s",
    "DNS resolution and SSRF filtering": "Résolution DNS et filtrage SSRF",
    "SSL/TLS diagnostics and expiry": "Diagnostic SSL/TLS et expirations",
    "HTTP headers audit": "Audit des en-têtes HTTP",
    "Cookie security analysis": "Analyse de sécurité des cookies",
    "WAF & CDN signature detection": "Détection signatures WAF & CDN",
    "AI report generation": "Génération du rapport IA",
    "Audit of %(domain)s": "Audit de %(domain)s",
    "the target": "la cible",
    ".": ",",
    # --- routes.py
    "Invalid credentials.": "Identifiants invalides.",
    "Invalid API key.": "Clé API invalide.",
    "You must certify that you are authorized to scan this domain.":
        "Vous devez certifier avoir l'autorisation de scanner ce domaine.",
    "Invalid domain": "Domaine invalide",
    "Action not allowed: resolution to a private IP detected.":
        "Action non autorisée : résolution vers une IP privée détectée.",
    "The domain '%(domain)s' could not be found or does not exist.":
        "Le domaine '%(domain)s' est introuvable ou n'existe pas.",
    "You have been logged out.": "Vous êtes déconnecté.",
    # --- dashboard.html : en-tête, causes d'arrêt
    "target": "cible",
    "Plain HTTP / HTTPS not enforced": "HTTP en clair / HTTPS non forcé",
    "TLS handshake failed (obsolete or incompatible protocol/cipher)":
        "Handshake TLS échoué (protocole/cipher obsolète ou incompatible)",
    "Invalid TLS certificate": "Certificat TLS invalide",
    "HTTPS not enforced": "HTTPS non forcé",
    "No HTTPS: no TLS handshake possible on port 443": "Aucun HTTPS : pas de handshake TLS possible sur le port 443",
    "no HTTPS": "pas de HTTPS",
    "Checks that do not depend on TLS (DNS and email: SPF, DMARC, DNSSEC, CAA, AXFR) and a plain-text HTTP read can still run. The result is a partial verdict, not scored.":
        "Les contrôles indépendants du TLS (DNS et e-mail : SPF, DMARC, DNSSEC, CAA, AXFR) et une lecture HTTP en clair peuvent encore tourner. Le résultat est un verdict partiel, non noté.",
    "Analyze the rest anyway": "Analyser le reste quand même",
    "TLS absent or unverifiable: the rest of the analysis is indicative only. Run it again once the certificate is in place.":
        "TLS absent ou non vérifiable : le reste de l'analyse est donné à titre indicatif. Relancez quand le certificat sera en place.",
    "Headers and cookies were read over plain HTTP.": "En-têtes et cookies lus en HTTP clair.",
    "Certificate chain": "Chaîne de certificats",
    "Incomplete": "Incomplète",
    "HTTPS enforcement": "HTTPS forcé",
    "Not enforced": "Non forcé",
    "The site also answers in plain text, without redirecting to HTTPS":
        "Le site répond aussi en clair, sans redirection vers HTTPS",
    "TLS chain incomplete: the server does not send the intermediate certificate. Browsers (Chrome, Firefox, Safari, Edge) compensate automatically via AIA, but strict clients do not.":
        "Chaîne TLS incomplète : le serveur ne fournit pas le certificat intermédiaire. Les navigateurs (Chrome, Firefox, Safari, Edge) compensent automatiquement via AIA, mais pas les clients stricts.",
    "Affected: code HTTP clients (Python requests/urllib, Go net/http, Java HttpsURLConnection, Node without an up-to-date CA bundle, curl/wget depending on config); server-to-server integrations and webhooks (Stripe, GitHub...) that validate strictly; mobile apps and SDKs with a limited trust store or pinning; connected and embedded devices (frozen trust store); mail clients (SMTP/IMAP STARTTLS); old Android (< 7). Fix: serve the fullchain (certificate + intermediate) on the server.":
        "Impactés : clients HTTP de code (Python requests/urllib, Go net/http, Java HttpsURLConnection, Node sans bundle CA à jour, curl/wget selon la config) ; intégrations serveur-à-serveur et webhooks (Stripe, GitHub…) qui valident strictement ; apps mobiles et SDK à trust store limité ou avec pinning ; objets connectés et embarqués (trust store figé) ; clients mail (SMTP/IMAP STARTTLS) ; vieux Android (< 7). Correctif : servir le fullchain (certificat + intermédiaire) côté serveur.",
    "Impact and fix": "Impacts et correctif",
    "TLS handshake failed": "handshake TLS échoué",
    "invalid certificate": "certificat invalide",
    "HTTPS connection": "Connexion HTTPS",
    "TLS handshake": "Handshake TLS",
    "Certificate": "Certificat",
    "partial TLS": "TLS partiel",
    "%(list)s was not read": "%(list)s non lu",
    "%(list)s were not read": "%(list)s non lus",
    # --- failles critiques, statuts
    "SSLv2/SSLv3 accepted": "SSLv2/SSLv3 accepté",
    "Broken cipher suite accepted (%(ciphers)s)": "Cipher suite cassée acceptée (%(ciphers)s)",
    "Open AXFR zone transfer": "Transfert de zone AXFR ouvert",
    "Active": "Actif",
    "Not verifiable": "Non vérifiable",
    "Missing": "Manquant",
    "Failed": "Échec",
    "Valid": "Valide",
    "Invalid": "Invalide",
    "Expired, self-signed or name mismatch": "Expiré, auto-signé ou nom non concordant",
    "Not verified": "Non vérifié",
    "Certificate verification did not complete": "La vérification du certificat n’a pas abouti",
    "accepted": "accepté",
    "refused": "refusé",
    "undetermined": "indéterminé",
    "Accepted": "Accepté",
    "Refused": "Refusé",
    "Undetermined": "Indéterminé",
    "Supported": "Supporté",
    "Not supported": "Non supporté",
    "Not scored": "Non noté",
    "Modern version missing": "Version moderne absente",
    "Weak ciphers": "Ciphers faibles",
    "Broken": "Cassé",
    "Legacy": "Legacy",
    "None": "Aucun",
    "No RC4, DES, 3DES, EXPORT, NULL, MD5 or anonymous suites": "Ni RC4, DES, 3DES, EXPORT, NULL, MD5 ni anonyme",
    "ECDHE/DHE or TLS 1.3": "ECDHE/DHE ou TLS 1.3",
    "Not active": "Absente",
    "No ECDHE/DHE suite accepted": "Aucune suite ECDHE/DHE acceptée",
    "Vulnerabilities": "Vulnérabilités",
    "Vulnerable": "Vulnérable",
    " · informational, not scored": " · informatif, non noté",
    "%(names)s inconclusive": "%(names)s non conclusif",
    "None found": "Aucune",
    "Unreachable": "Injoignable",
    "sslyze could not reach port 443": "sslyze n’a pas pu joindre le port 443",
    "Skipped": "Ignorée",
    "No public IP resolved for the domain": "Aucune IP publique résolue pour le domaine",
    "Error": "Erreur",
    "sslyze analysis failed": "Analyse sslyze en échec",
    "Timed out": "Délai dépassé",
    "sslyze analysis aborted: the server responded too slowly":
        "Analyse sslyze abandonnée : le serveur a répondu trop lentement",
    "Deep analysis": "Analyse approfondie",
    "Not run": "Non exécutée",
    "Scan interrupted: %(reason)s": "Scan interrompu : %(reason)s",
    "Audit predates the deep TLS analysis": "Audit antérieur à l’analyse TLS approfondie",
    # --- DNS
    "DNS query failed": "Requête DNS en échec",
    "Check missing from this audit": "Contrôle absent de cet audit",
    "Absent": "Absent",
    "No v=spf1 record": "Aucun enregistrement v=spf1",
    "Permissive": "Permissif",
    "+all: any sender allowed": "+all : tout expéditeur autorisé",
    "Present": "Présent",
    "Termination %(t)s": "Terminaison %(t)s",
    "No _dmarc record": "Aucun enregistrement _dmarc",
    "Monitoring only, nothing rejected": "Surveillance seule, aucun rejet",
    "p= policy not read": "Politique p= non lue",
    "Found": "Trouvé",
    " · informational": " · informatif",
    "Not found": "Non trouvé",
    "%(n)s common selectors tested, not exhaustive": "%(n)s sélecteurs courants testés, non exhaustif",
    "DNSKEY/DS published": "DNSKEY/DS publiés",
    "Unsigned DNS responses": "Réponses DNS non signées",
    "Any CA may issue a certificate": "Toute AC peut émettre un certificat",
    "Open": "Ouvert",
    "Zone transferable via %(ns)s": "Zone transférable via %(ns)s",
    "Refused by %(n)s nameserver(s)": "Refusé par %(n)s serveur(s) de noms",
    "Not tested": "Non testé",
    "No public nameserver resolved": "Aucun serveur de noms public résolu",
    # --- verdict
    "compliant": "conforme",
    "to watch": "à surveiller",
    "vulnerable": "vulnérable",
    "not verified": "non vérifié",
    "Solid posture": "Posture solide",
    "Encryption, DNS and headers are well configured: little is left to fix.":
        "Chiffrement, DNS et en-têtes sont bien configurés : il reste peu de choses à corriger.",
    "Good posture": "Bonne posture",
    "The foundation is sound; a few hardening steps remain.":
        "La base est saine ; quelques durcissements restent à faire.",
    "Fair posture": "Posture correcte",
    "Notable gaps pull the score down.": "Des lacunes notables tirent la note vers le bas.",
    "Weak posture": "Posture fragile",
    "Several protections are missing or only partial.": "Plusieurs protections manquent ou ne sont que partielles.",
    "Critical posture": "Posture critique",
    "A major failure exposes the domain.": "Une défaillance majeure expose le domaine.",
    "Undetermined posture": "Posture indéterminée",
    "The grade could not be calculated.": "Le grade n’a pas pu être calculé.",
    "no impact on the score": "aucun impact sur la note",
    "Secure": "Sécurisé",
    "Exposed": "Exposé",
    "Not detected": "Non détecté",
    "Headers": "En-têtes",
    # --- à corriger
    "The site answers in plain text: the scan stopped and the score is capped.":
        "Le site répond en clair : le scan s’est arrêté et la note est plafonnée.",
    "The scan stopped: the score is capped.": "Le scan s’est arrêté : la note est plafonnée.",
    "tls · cap": "tls · plafond",
    "%(name)s: %(label)s": "%(name)s : %(label)s",
    "Header %(name)s missing": "En-tête %(name)s manquant",
    "Absent from the observed HTTP response.": "Absent de la réponse HTTP observée.",
    "headers": "en-têtes",
    "Cookie %(name)s exposed": "Cookie %(name)s exposé",
    "This domain was already scanned %(min)s min ago in this session: here is the existing report.":
        "Ce domaine a déjà été scanné il y a %(min)s min dans cette session : voici le rapport existant.",
    "Force a new scan": "Forcer un nouveau scan",
    # --- hero
    "Incomplete analysis: overall posture cannot be assessed, no score":
        "Analyse incomplète : posture globale non évaluable, aucune note",
    "Analysis": "Analyse",
    "incomplete": "incomplète",
    "NOT SCORED": "NON NOTÉ",
    "Score %(score)s out of 100, grade %(grade)s": "Score %(score)s sur 100, grade %(grade)s",
    ", capped (computed score %(raw)s)": ", plafonné (score calculé %(raw)s)",
    "PARTIAL VERDICT": "VERDICT PARTIEL",
    "CERTIFIED VERDICT": "VERDICT CERTIFIÉ",
    "Incomplete analysis.": "Analyse incomplète.",
    ", capped": ", plafonnée",
    ", incomplete analysis": ", analyse incomplète",
    "the site blocks HTTP analysis (%(name)s challenge detected)":
        "le site bloque l'analyse HTTP (challenge %(name)s détecté)",
    "Overall posture cannot be assessed: %(why)s. The observable elements are shown below.":
        "Posture globale non évaluable : %(why)s. Les éléments observables sont présentés ci-dessous.",
    "The score only covers what could be observed: %(why)s: the site served a %(name)s challenge page instead of its page, with no deduction.":
        "La note ne porte que sur ce qui a pu être observé : %(why)s : le site a servi une page de challenge %(name)s à la place de sa page, sans déduction.",
    "The score only covers what could be observed: %(why)s, with no deduction.":
        "La note ne porte que sur ce qui a pu être observé : %(why)s, sans déduction.",
    "server": "serveur",
    "analyzed": "analysé",
    "Not read or partial: %(parts)s. The score only covers what could be observed.":
        "Non lu ou partiel : %(parts)s. La note ne porte que sur ce qui a pu être observé.",
    "Incomplete analysis": "Analyse incomplète",
    "critical": "critiques",
    "medium": "moyennes",
    "low": "faibles",
    "Stack": "Stack",
    "View scoring scale": "Voir le barème",
    "Score capped at %(grade)s (%(max)s): %(reasons)s.": "Note plafonnée à %(grade)s (%(max)s) : %(reasons)s.",
    "; ": " ; ",
    "Score before cap: %(raw)s/100. A serious flaw is not offset by the other categories.":
        "Score calculé avant plafond : %(raw)s/100. Une faille grave ne se compense pas par les autres catégories.",
    "Critical flaw: %(list)s.": "Faille critique : %(list)s.",
    "Critical flaws: %(list)s.": "Failles critiques : %(list)s.",
    "Observed despite the incomplete analysis: to be handled even without an overall score.":
        "Observée malgré l'analyse incomplète : à traiter même sans note globale.",
    "Cap not triggered: the computed score is already below the matching threshold.":
        "Plafond non déclenché : le score calculé est déjà sous le seuil correspondant.",
    "No category could be measured: the score is set by this cap (%(score)s/100).":
        "Aucune catégorie n'a pu être mesurée : la note est fixée par ce plafond (%(score)s/100).",
    "Attack surface": "Surface d'attaque",
    "Protection estimated by AI · 5 axes": "Protection estimée par l'IA · 5 axes",
    "Radar of protections estimated by AI, from 0 to 100": "Radar des protections estimées par l'IA, de 0 à 100",
    "Estimate unavailable.": "Estimation indisponible.",
    "The AI report returned no usable values for this scan.":
        "Le rapport IA n'a pas renvoyé de valeurs exploitables pour ce scan.",
    # --- catégories
    "Scores by category": "Notes par catégorie",
    "no average: partial verdict": "aucune moyenne : verdict partiel",
    "weighted average": "moyenne pondérée",
    "not evaluated": "non évalué",
    "Not evaluated": "Non évalué",
    "Scan interrupted (%(reason)s): this category was not measured.":
        "Scan interrompu (%(reason)s) : cette catégorie n'a pas été mesurée.",
    "%(name)s challenge page served instead of the site: not verifiable (neither “missing” nor 0/100).":
        "Page de challenge %(name)s servie à la place du site : non vérifiable (ni « manquant », ni 0/100).",
    "HTTPS response not read: check not verifiable, excluded from the average.":
        "Réponse HTTPS non lue : contrôle non vérifiable, exclu de la moyenne.",
    "Check not run for this audit: excluded from the average.":
        "Contrôle non exécuté pour cet audit : exclu de la moyenne.",
    " out of 100": " sur 100",
    "No deduction": "Aucune déduction",
    "DNS checks not run: default score, not meaningful.": "Contrôles DNS non exécutés : note par défaut, non significative.",
    "Deep analysis unavailable: only the certificate is scored.":
        "Analyse approfondie indisponible : seul le certificat est noté.",
    "Partial TLS analysis": "Analyse TLS partielle",
    ": ": " : ",
    "%(n)s protocol not verified, no deduction for this check.":
        "%(n)s protocole non vérifié, aucune déduction pour ce contrôle.",
    "%(n)s protocols not verified, no deduction for these checks.":
        "%(n)s protocoles non vérifiés, aucune déduction pour ces contrôles.",
    "No cookie set: nothing at risk.": "Aucun cookie posé : rien à risque.",
    "overall score not calculated: %(why)s, no renormalized average":
        "note globale non calculée : %(why)s, aucune moyenne renormalisée",
    "(on %(pct)s evaluated)": "(sur %(pct)s évalués)",
    "infra bonus": "bonus infra",
    "computed score": "score calculé",
    "no category evaluated: the score is the cap": "aucune catégorie évaluée : la note est celle du plafond",
    "cap": "plafond",
    "final": "final",
    # --- infrastructure, évolution, IA
    "Infrastructure": "Infrastructure",
    "Protection": "Protection",
    "(%(names)s: no bonus)": "(%(names)s : sans bonus)",
    "Server": "Serveur",
    "TLS certificate": "Certificat TLS",
    "Issuer": "Émetteur",
    "Expiry": "Expiration",
    "Self-hosted server — no third-party protection layer identified":
        "Serveur auto-hébergé — aucune couche de protection tierce identifiée",
    "Score trend": "Évolution du score",
    "last %(n)s scored scans": "%(n)s derniers scans notés",
    " · this partial scan is not scored": " · ce scan partiel n'est pas noté",
    "Score from %(first)s to %(last)s over %(n)s scans of %(domain)s":
        "Score de %(first)s à %(last)s sur %(n)s scans de %(domain)s",
    "AI analysis": "Analyse IA",
    "LLM-generated · to be verified": "généré par LLM · à vérifier",
    "This report was generated in %(language)s.": "Ce rapport a été généré en %(language)s.",
    "Executive summary": "Résumé exécutif",
    "Key technical points": "Points techniques clés",
    "AI analysis unavailable.": "Analyse IA indisponible.",
    "Try again or check the configuration (model and API key) from the log-out screen, then run a new scan.":
        "Réessayez ou vérifiez la configuration (modèle et clé API) depuis la déconnexion, puis relancez un scan.",
    "The score and all checks on this page do not depend on the AI.":
        "Le score et tous les contrôles de cette page ne dépendent pas de l'IA.",
    "Vulnerability surface": "Surface de vulnérabilités",
    "checks run": "contrôles exécutés",
    "Fix first": "À corriger en priorité",
    "%(n)s item": "%(n)s point",
    "%(n)s items": "%(n)s points",
    "No blocking issue observed in this scan.": "Aucun point bloquant observé sur ce scan.",
    # --- panneaux
    "weight": "poids",
    "partial": "partielle",
    "not verifiable": "non vérifiable",
    "no cookie": "aucun cookie",
    "secure": "sécurisés",
    "Cookies not verifiable: HTTPS response not read.": "Cookies non vérifiables : réponse HTTPS non lue.",
    "No cookie detected.": "Aucun cookie détecté.",
    "DNS & email": "DNS & messagerie",
    "Not verified (earlier audit)": "Non vérifié (audit antérieur)",
    "Email/zone DNS evaluated on": "DNS e-mail/zone évalués sur",
    "organization domain of %(domain)s": "domaine d'organisation de %(domain)s",
    "Scan interrupted (%(reason)s): SPF, DMARC, DKIM, DNSSEC, CAA and AXFR not checked.":
        "Scan interrompu (%(reason)s) : SPF, DMARC, DKIM, DNSSEC, CAA et AXFR non contrôlés.",
    "Audit predates the SPF, DMARC, DKIM, DNSSEC, CAA and AXFR checks. Run a new scan to get them.":
        "Audit antérieur aux contrôles SPF, DMARC, DKIM, DNSSEC, CAA et AXFR. Relancez un scan pour les obtenir.",
    "Security headers": "En-têtes de sécurité",
    "active": "actifs",
    "No header analyzed: scan interrupted (%(reason)s).": "Aucun en-tête analysé : scan interrompu (%(reason)s).",
    "No header analyzed.": "Aucun en-tête analysé.",
    "Score calculation": "Calcul du score",
    "scale v1 · base 50": "barème v1 · base 50",
    "Final score (bounded 0–100)": "Score final (borné 0–100)",
    "Report generated by SecuScope · non-intrusive external audit · %(n)s checks run":
        "Rapport généré par SecuScope · audit externe non intrusif · %(n)s contrôles exécutés",
    # --- barème
    "SecuScope scoring scale": "Barème SecuScope",
    "Close scoring scale": "Fermer le barème",
    "Solid configuration across all four categories, no capping flaw.":
        "Configuration solide sur les quatre catégories, aucune faille plafonnante.",
    "Good foundation; a few moderate deductions in one or two categories.":
        "Bonne base ; quelques déductions modérées dans une ou deux catégories.",
    "Notable gaps, or cap C: SSLv2/SSLv3 accepted, broken cipher suite accepted, open AXFR zone transfer.":
        "Lacunes notables, ou plafond C : SSLv2/SSLv3 accepté, cipher suite cassée acceptée, transfert de zone AXFR ouvert.",
    "Partial protections, or cap D: invalid TLS certificate.":
        "Protections partielles, ou plafond D : certificat TLS invalide.",
    "Major failures, or cap F: plain HTTP, HTTPS not enforced or TLS handshake failed.":
        "Défaillances majeures, ou plafond F : HTTP en clair, HTTPS non forcé ou handshake TLS échoué.",
    "Optimal security. TLS/SSL operational, web application firewall (WAF) active or protected infrastructure.":
        "Sécurité optimale. TLS/SSL opérationnel, pare-feu applicatif (WAF) actif ou infrastructure protégée.",
    "Robust configuration. Encryption validated but some minor defensive headers are missing.":
        "Configuration robuste. Chiffrement validé mais absence de certains en-têtes défensifs mineurs.",
    "Decent baseline. Several defensive headers or cookie attributes are missing.":
        "Socle correct. Plusieurs en-têtes défensifs ou attributs de cookies manquent.",
    "Partial protections. HTTP and cookie hardening to be addressed first.":
        "Protections partielles. Durcissement HTTP et cookies à reprendre en priorité.",
    "Critical vulnerabilities. Invalid TLS certificate, site reachable in plain text (HTTP not enforced) or no protections at all.":
        "Vulnérabilités critiques. Certificat TLS invalide, site accessible en clair (HTTP non forcé) ou absence totale de protections.",
    "this site": "ce site",
    "Weighting": "Pondération",
    "Infrastructure bonus (WAF/CDN)": "Bonus infrastructure (WAF/CDN)",
    "+5 / layer, max +10": "+5 / couche, max +10",
    "Each category starts at 100 and deducts for each observed problem. An unverified check deducts nothing.":
        "Chaque catégorie part de 100 et déduit par problème observé. Un contrôle non vérifié ne déduit rien.",
    "Caps (critical flaw)": "Plafonds (faille critique)",
    "Broken cipher suite accepted (RC4, DES, EXPORT, NULL, MD5, anonymous)":
        "Cipher suite cassée acceptée (RC4, DES, EXPORT, NULL, MD5, anonyme)",
    "Applied after the bonus: a serious flaw cannot be bought back.":
        "Appliqués après le bonus : une faille grave ne se rachète pas.",
    "Close": "Fermer",
}

# Libellés stockés (français) -> anglais. Clés exactes produites par scoring.py / scanner.py.
STORED_EN = {
    # scoring.py : déductions
    "Certificat invalide, expiré ou ne correspond pas au domaine": "Certificate invalid, expired or does not match the domain",
    "SSLv2/SSLv3 accepté": "SSLv2/SSLv3 accepted",
    "TLS 1.0/1.1 accepté": "TLS 1.0/1.1 accepted",
    "Forward secrecy absente": "Forward secrecy missing",
    "TLS 1.3 non supporté": "TLS 1.3 not supported",
    "SPF absent": "SPF missing",
    "SPF permissif (+all)": "Permissive SPF (+all)",
    "DMARC absent": "DMARC missing",
    "DMARC en p=none (surveillance seule)": "DMARC at p=none (monitoring only)",
    "Transfert de zone AXFR ouvert": "Open AXFR zone transfer",
    "DNSSEC absent": "DNSSEC missing",
    "CAA absent": "CAA missing",
    # scoring.py : raisons de plafond (minuscules) et causes d'arrêt
    "certificat TLS invalide": "invalid TLS certificate",
    "transfert de zone AXFR ouvert": "open AXFR zone transfer",
    "HTTP en clair / HTTPS non forcé": "Plain HTTP / HTTPS not enforced",
    "Handshake TLS échoué (protocole/cipher obsolète ou incompatible)":
        "TLS handshake failed (obsolete or incompatible protocol/cipher)",
    "Certificat TLS invalide": "Invalid TLS certificate",
    "Aucun HTTPS : pas de handshake TLS possible sur le port 443": "No HTTPS: no TLS handshake possible on port 443",
    "Lecture HTTP en clair impossible : en-têtes et cookies non vérifiables": "Plain-text HTTP read impossible: headers and cookies not verifiable",
    "En-têtes et cookies lus en clair (HTTP) : à titre indicatif": "Headers and cookies read over plain HTTP: indicative only",
    "Chaîne TLS incomplète (certificat intermédiaire non servi)": "Incomplete TLS chain (intermediate certificate not served)",
    "HTTPS non forcé (site accessible en clair)": "HTTPS not enforced (site reachable in plain text)",
    "Chaîne TLS incomplète : certificat intermédiaire non servi par le serveur": "Incomplete TLS chain: intermediate certificate not served by the server",
    "HTTPS non forcé : le site répond aussi en clair, sans redirection vers HTTPS": "HTTPS not enforced: the site also answers in plain text, without redirecting to HTTPS",
    "HTTPS redirige vers HTTP : le site finit en clair": "HTTPS redirects to HTTP: the site ends up in plain text",
    # scoring.py : catégories
    "En-têtes HTTP": "HTTP headers",
    # scanner.py
    "Non détecté": "Not detected",
    "Inconnu": "Unknown",
    "Manquant": "Missing",
    "Présent": "Present",
    "Présent (www)": "Present (www)",
    "Non vérifiable": "Not verifiable",
    "Masqué": "Hidden",
    "BLOQUÉ": "Blocked",
    "ACTIF": "Active",
}

STORED_EN_PATTERNS = [
    (re.compile(r"^Cipher suite cassée \((.*)\)$"), r"Broken cipher suite (\1)"),
    (re.compile(r"^Cipher suite legacy \((.*)\)$"), r"Legacy cipher suite (\1)"),
    (re.compile(r"^cipher suite cassée acceptée \((.*)\)$"), r"broken cipher suite accepted (\1)"),
    (re.compile(r"^(Secure|HttpOnly|SameSite) manquant sur (\d+)/(\d+) cookie\(s\)$"), r"\1 missing on \2/\3 cookie(s)"),
    (re.compile(r"^en-tête (.*) observé$"), r"header \1 observed"),
]
