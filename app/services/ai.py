from google import genai
import logging
import json
import time

logger = logging.getLogger(__name__)

DEFAULT_RISKS = {"mitm": 0, "xss": 0, "clickjacking": 0, "sniffing": 0, "waf": 0}


def _fallback_report(message):
    return {
        "executive": "Erreur IA",
        "technical": [message],
        "risks": DEFAULT_RISKS.copy(),
    }


def _extract_json_object(text):
    clean_text = (text or "").replace("```json", "").replace("```", "").strip()
    try:
        return json.loads(clean_text)
    except json.JSONDecodeError:
        start = clean_text.find("{")
        end = clean_text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise
        return json.loads(clean_text[start:end + 1])


def _normalize_report(data):
    if not isinstance(data, dict):
        return _fallback_report("Réponse IA invalide")

    executive = data.get("executive")
    technical = data.get("technical")
    risks = data.get("risks")

    if not isinstance(executive, str) or not executive.strip():
        executive = "Rapport IA généré sans résumé exploitable."

    if isinstance(technical, str):
        technical = [technical]
    elif not isinstance(technical, list):
        technical = []

    normalized_risks = DEFAULT_RISKS.copy()
    if isinstance(risks, dict):
        for key in normalized_risks:
            try:
                normalized_risks[key] = max(0, min(100, int(risks.get(key, 0))))
            except (TypeError, ValueError):
                normalized_risks[key] = 0

    return {
        "executive": executive.strip(),
        "technical": [str(item) for item in technical[:6]],
        "risks": normalized_risks,
    }


def _format_dns_security(dns_sec):
    """Résume dns_security pour le prompt ; tolère l'absence de la clé ou d'un contrôle."""
    if not isinstance(dns_sec, dict) or not dns_sec:
        return "- Analyse DNS non disponible pour cet audit (ne pas en tirer de conclusion)."

    def section(key):
        value = dns_sec.get(key)
        return value if isinstance(value, dict) else {}

    def unverified(info):
        return info.get("status", "error") == "error"

    lines = []

    spf = section("spf")
    if unverified(spf):
        lines.append("- SPF : non vérifié (erreur DNS)")
    elif spf["status"] == "absent":
        lines.append("- SPF : ABSENT (usurpation d'e-mail facilitée)")
    else:
        termination = spf.get("termination")
        note = " (PERMISSIF : autorise tout expéditeur)" if termination == "+all" else ""
        lines.append(f"- SPF : présent, terminaison {termination}{note}")

    dmarc = section("dmarc")
    if unverified(dmarc):
        lines.append("- DMARC : non vérifié (erreur DNS)")
    elif dmarc["status"] == "absent":
        lines.append("- DMARC : ABSENT")
    else:
        policy = dmarc.get("policy")
        note = " (surveillance seule, aucun blocage)" if policy == "none" else ""
        lines.append(f"- DMARC : présent, p={policy}{note}")

    dnssec = section("dnssec")
    if unverified(dnssec):
        lines.append("- DNSSEC : non vérifié (erreur DNS)")
    else:
        lines.append(f"- DNSSEC : {'actif' if dnssec.get('enabled') else 'inactif'}")

    caa = section("caa")
    if unverified(caa):
        lines.append("- CAA : non vérifié (erreur DNS)")
    elif caa["status"] == "present":
        lines.append(f"- CAA : présent, AC autorisées : {caa.get('authorities', [])}")
    else:
        lines.append("- CAA : absent")

    axfr = section("axfr")
    if unverified(axfr):
        lines.append("- Transfert de zone AXFR : non vérifié (erreur DNS)")
    elif axfr["status"] == "vulnerable":
        lines.append(
            "- Transfert de zone AXFR : OUVERT = FAILLE CRITIQUE sur "
            f"{axfr.get('vulnerable_nameservers', [])} (toute la zone DNS est exposée)"
        )
    else:
        lines.append("- Transfert de zone AXFR : fermé")

    dkim = section("dkim")
    if not unverified(dkim):
        found = dkim.get("selectors_found", [])
        lines.append(
            f"- DKIM (indice, sélecteurs courants uniquement) : {found}"
            if found else
            "- DKIM (indice) : aucun sélecteur courant trouvé (n'implique pas l'absence de DKIM)"
        )

    return "\n".join(lines)


def generate_report(scan_data, api_key, model_id):
    if not api_key:
        return {"executive": "Pas de clé", "technical": [], "risks": DEFAULT_RISKS.copy()}
    try:
        client = genai.Client(api_key=api_key)
        dns_summary = _format_dns_security(scan_data.get('dns_security', {}))

        prompt = f"""
Tu es un expert en cybersécurité (Audit Black Box).
Analyse ce domaine : {scan_data['domain']}

Données collectées :
- Score actuel : {scan_data.get('numeric_score', 'N/A')}/100
- SSL Issuer : {scan_data['ssl'].get('issuer')}
- WAF détecté : {scan_data['waf_detected']}
- Serveur : {scan_data.get('server')}
- Stack technique : {scan_data.get('tech_stack', [])}
- Headers présents : {[k for k,v in scan_data.get('headers', {}).items() if '✅' in str(v)]}
- Headers manquants : {scan_data['missing_headers']}
  (réellement absents de la réponse HTTP ; un CDN/WAF n'implique aucune protection de leur part, recommande de les ajouter)
- Cookies : {scan_data.get('cookies_security', [])}

Sécurité DNS / e-mail :
{dns_summary}

CONSIGNE : tiens compte des failles DNS ci-dessus dans "executive" et "technical". Une faille
marquée CRITIQUE (ex. AXFR ouvert) doit apparaître comme point critique : ne qualifie pas le
site de robuste dans ce cas. Ne déduis rien d'un contrôle « non vérifié » ou « non disponible ».

TÂCHE : Génère un JSON BRUT UNIQUEMENT (pas de markdown, pas de texte avant/après) avec 3 clés :
1. "executive": Résumé dirigeant (2 phrases, ton professionnel).
2. "technical": Liste de 4 points techniques actionnables précis.
3. "risks": Objet JSON avec niveau de protection (0-100) pour :
   - "mitm": (basé sur HSTS + SSL valide)
   - "xss": (basé sur CSP)
   - "clickjacking": (basé sur X-Frame-Options)
   - "sniffing": (basé sur X-Content-Type-Options)
   - "waf": (basé sur WAF détecté + infrastructure)
"""
        


        for attempt in range(3):
            try:
                response = client.models.generate_content(model=model_id, contents=prompt)
                break
            except Exception as e:
                if "503" in str(e) and attempt < 2:
                    time.sleep(3)
                    continue
                raise e
        return _normalize_report(_extract_json_object(response.text))
    except Exception as e:
        logger.error(f"Erreur GenAI ({model_id}) : {e}")
        return _fallback_report(str(e))
