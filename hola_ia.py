import time
from dotenv import load_dotenv
from google import genai
from google.genai import types
from config import MODELOS
MODELO = MODELOS["gemini"]  # este script es la prueba de Gemini

load_dotenv()
cliente = genai.Client(http_options=types.HttpOptions(timeout=120_000))

ajustes = types.GenerateContentConfig(
      thinking_config=types.ThinkingConfig(thinking_level=types.ThinkingLevel.LOW),
)

inicio = time.time()
respuesta = cliente.models.generate_content(
    model=MODELO,
    contents="Explica en una sola frase qué es una regla Sigma.",
    config=ajustes,
)
duracion = time.time() - inicio

print("Modelo:", MODELO)
print(f"Tiempo de respuesta: {duracion:.1f} s")
print(respuesta.text)
uso = respuesta.usage_metadata
print("Tokens de la pregunta:  ", uso.prompt_token_count)
print("Tokens de razonamiento: ", uso.thoughts_token_count)
print("Tokens de la respuesta: ", uso.candidates_token_count)