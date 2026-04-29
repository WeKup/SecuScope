from google import genai
import logging
import json
import time

logger = logging.getLogger(__name__)

def generate_report(scan_data, api_key, model_id):
    if not api_key:
        return {"executive": "Pas de clé", "technical": [], "risks": {}}
    try:
        client = genai.Client(api_key=api_key)
        
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
- Cookies : {scan_data.get('cookies_security', [])}

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
        clean_text = response.text.replace("```json", "").replace("```", "").strip()
        return json.loads(clean_text)
    except Exception as e:
        logger.error(f"Erreur GenAI ({model_id}) : {e}")
        return {
            "executive": "Erreur IA", 
            "technical": [str(e)],
            "risks": {"mitm": 0, "xss": 0, "clickjacking": 0, "sniffing": 0, "waf": 0}
        }