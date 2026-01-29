from google import genai
import logging
import json
logger = logging.getLogger(__name__)
def generate_report(scan_data,api_key, model_id):
    
    
    if not api_key:
        return {"executive": "Pas de clé", "technical": [], "risks": {}}

    try:
        client = genai.Client(api_key=api_key)

        prompt = f"""
        Tu es un expert en cybersécurité (Audit Black Box).
        Analyse ce domaine : {scan_data['domain']}
        Données : SSL={scan_data['ssl'].get('issuer')}, WAF={scan_data['waf_detected']}, Headers manquants={scan_data['missing_headers']}
        
        TÂCHE : Génère un JSON BRUT avec 3 clés :
        1. "executive": Résumé court (2 phrases).
        2. "technical": Liste de 3 points techniques.
        3. "risks": Un objet JSON estimant le NIVEAU DE PROTECTION (0 = Nul, 100 = Parfait) pour ces 5 axes, basé sur les headers présents/absents :
           - "mitm": Protection contre Man-in-the-Middle (HSTS, SSL).
           - "xss": Protection contre XSS (CSP, X-XSS-Protection).
           - "clickjacking": Protection contre Clickjacking (X-Frame-Options).
           - "sniffing": Protection MIME Sniffing (X-Content-Type).
           - "waf": Protection périmétrique globale.
        """

        response = client.models.generate_content(
            model=model_id,
            contents=prompt
        )
        
        clean_text = response.text.replace("```json", "").replace("```", "").strip()
        return json.loads(clean_text)

    except Exception as e:
        logger.error(f"Erreur GenAI ({model_id}) : {e}")
        return {
            "executive": "Erreur IA", 
            "technical": [str(e)],
            "risks": {"mitm": 0, "xss": 0, "clickjacking": 0, "sniffing": 0, "waf": 0}
        }