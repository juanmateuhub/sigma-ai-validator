import time
from dotenv import load_dotenv
from google import genai
from google.genai import types

MODELOS = [
    "gemini-3.8-flash",
    "gemini-3.7-flash",
    "gemini-3.6-flash",
    "gemini-3.5-flash",
    "gemini-3.5-flash-lite",
    "gemini-3.1-flash-lite",
]

load_dotenv()
# Timeout de 30 s y un solo intento: si el servicio está saturado, queremos saberlo ya
cliente = genai.Client(http_options=types.HttpOptions(
    timeout=30_000,
    retry_options=types.HttpRetryOptions(attempts=1),
))

ajustes = types.GenerateContentConfig(
    thinking_config=types.ThinkingConfig(thinking_level=types.ThinkingLevel.LOW),
)

for modelo in MODELOS:
    inicio = time.time()
    try:
        respuesta = cliente.models.generate_content(
            model=modelo,
            contents="Responde solo con la palabra: hola",
            config=ajustes,
        )
        duracion = time.time() - inicio
        print(f"OK     {modelo:25} {duracion:5.1f} s  -> {respuesta.text.strip()}")
    except Exception as error:
        duracion = time.time() - inicio
        # Primera línea del error: basta para distinguir 404, 400 y 504
        motivo = str(error).splitlines()[0][:100]
        print(f"FALLO  {modelo:25} {duracion:5.1f} s  -> {motivo}")
