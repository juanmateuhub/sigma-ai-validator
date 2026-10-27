import time
from ollama import Client
from config import MODELO

# El servidor de Ollama corre en local; el primer uso tarda más porque carga el modelo en la GPU
cliente = Client(host="http://localhost:11434", timeout=300)

# Ollama recorta por defecto el contexto; con 8192 tokens caben la regla y dos correcciones
VENTANA_CONTEXTO = 8192


def preguntar(instrucciones, conversacion):
    """Envía la conversación al modelo local y devuelve su texto y los datos de la llamada.

    Misma interfaz que ia_gemini.preguntar: 'conversacion' es una lista de pares
    (rol, texto), con rol "user" o "model". En local no hay cuotas, así que no se reintenta.
    """
    mensajes = [{"role": "system", "content": instrucciones}]
    # Ollama llama "assistant" a lo que Gemini llama "model"
    mensajes += [{"role": "assistant" if rol == "model" else rol, "content": texto}
                 for rol, texto in conversacion]

    inicio = time.time()
    respuesta = cliente.chat(model=MODELO, messages=mensajes, options={"num_ctx": VENTANA_CONTEXTO})
    datos = {
        "modelo": MODELO,
        "segundos": round(time.time() - inicio, 1),
        "tokens_pregunta": respuesta.prompt_eval_count or 0,
        "tokens_razonamiento": 0,
        "tokens_respuesta": respuesta.eval_count or 0,
    }
    return respuesta.message.content, datos
