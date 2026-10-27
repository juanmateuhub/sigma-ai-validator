# Configuración del proyecto
PROVEEDOR = "ollama"  # "gemini" u "ollama"
MODELOS = {
    "gemini": "gemini-3.6-flash",
    "ollama": "qwen2.5-coder:7b",
}
MODELO = MODELOS[PROVEEDOR]
