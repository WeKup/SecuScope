from google import genai
import os
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("GOOGLE_API_KEY")

if not api_key:
    print("❌ Erreur : Pas de clé API trouvée dans .env")
    exit()

try:
    client = genai.Client(api_key=api_key)
    print(f"✅ Clé trouvée : {api_key[:5]}...")
    print("\n🔍 Recherche des modèles disponibles pour toi...")
    
    # On liste les modèles
    pager = client.models.list(config={"page_size": 100})
    
    found = False
    for model in pager:
        # On affiche seulement les modèles "gemini" qui génèrent du contenu
        if "gemini" in model.name:
            print(f"👉 {model.name}")
            found = True
            
    if not found:
        print("⚠️ Aucun modèle Gemini trouvé. Vérifie tes droits API.")

except Exception as e:
    print(f"\n❌ Erreur fatale : {e}")