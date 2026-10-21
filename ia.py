import re
import time
from dotenv import load_dotenv
from google import genai
from google.genai import errors, types
from config import MODELO

load_dotenv()
# Un solo intento por petición: los reintentos por límite de cuota los gestionamos aquí
cliente = genai.Client(http_options=types.HttpOptions(
    timeout=120_000,
    retry_options=types.HttpRetryOptions(attempts=1),
))


def preguntar(instrucciones, conversacion, max_esperas=3):
    """Envía la conversación al modelo y devuelve su texto y los datos de la llamada.

    'conversacion' es una lista de pares (rol, texto), con rol "user" o "model".
    Si se supera el límite de peticiones por minuto (429), espera lo que indica
    la API; si el servicio está saturado (503, 504), espera 10, 20, 40... segundos.
    Reintenta como mucho 'max_esperas' veces.
    """
    ajustes = types.GenerateContentConfig(
        system_instruction=instrucciones,
        thinking_config=types.ThinkingConfig(thinking_level=types.ThinkingLevel.LOW),
    )
    contenidos = [types.Content(role=rol, parts=[types.Part(text=texto)]) for rol, texto in conversacion]

    for espera in range(max_esperas + 1):
        inicio = time.time()
        try:
            respuesta = cliente.models.generate_content(model=MODELO, contents=contenidos, config=ajustes)
            break
        except errors.APIError as error:
            if error.code not in (429, 503, 504) or espera == max_esperas:
                raise
            if error.code == 429:
                # El mensaje de error dice cuánto esperar: "Please retry in 57.2s"
                pausa = re.search(r"retry in ([\d.]+)s", str(error))
                segundos = float(pausa.group(1)) + 1 if pausa else 60
            else:
                segundos = 10 * 2 ** espera
            print(f"  (error {error.code} de la API; espero {segundos:.0f} s y reintento)")
            time.sleep(segundos)

    uso = respuesta.usage_metadata
    datos = {
        "modelo": MODELO,
        "segundos": round(time.time() - inicio, 1),
        "tokens_pregunta": uso.prompt_token_count,
        "tokens_razonamiento": uso.thoughts_token_count or 0,
        "tokens_respuesta": uso.candidates_token_count,
    }
    return respuesta.text, datos
