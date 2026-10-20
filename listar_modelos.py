from dotenv import load_dotenv
from google import genai

load_dotenv()
cliente = genai.Client()

for modelo in cliente.models.list():
    if "generateContent" in (modelo.supported_actions or []) and "flash" in modelo.name:
        print(modelo.name)