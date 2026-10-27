# Capa intercambiable: el resto del proyecto importa preguntar() de aquí,
# y config.PROVEEDOR decide qué módulo responde
from config import PROVEEDOR

if PROVEEDOR == "ollama":
    from ia_ollama import preguntar
elif PROVEEDOR == "gemini":
    from ia_gemini import preguntar
else:
    raise ValueError(f"PROVEEDOR desconocido en config.py: {PROVEEDOR!r}")
