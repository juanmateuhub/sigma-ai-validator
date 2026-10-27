# Configuración del proyecto
import os

PROVEEDOR = "ollama"  # "gemini" u "ollama"
MODELOS = {
    "gemini": "gemini-3.6-flash",
    "ollama": "qwen2.5-coder:7b",
}
# Para probar otro modelo sin editar este archivo: $env:MODELO = "qwen3:8b"
MODELO = os.environ.get("MODELO") or MODELOS[PROVEEDOR]
