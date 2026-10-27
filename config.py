# Configuración del proyecto
import os

PROVEEDOR = os.environ.get("PROVEEDOR", "ollama")  # "gemini" u "ollama"
MODELOS = {
    "gemini": "gemini-3.6-flash",
    "ollama": "qwen2.5-coder:7b",
}
# Para probar otro modelo sin editar este archivo: $env:MODELO = "qwen3:8b"
MODELO = os.environ.get("MODELO") or MODELOS[PROVEEDOR]
# El prompt incluye una regla de ejemplo (few-shot); para medir sin ella: $env:CON_EJEMPLO = "0"
CON_EJEMPLO = os.environ.get("CON_EJEMPLO", "1") == "1"
