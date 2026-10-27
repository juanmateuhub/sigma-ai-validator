import re
import sys
from datetime import datetime
from pathlib import Path
from config import CON_EJEMPLO
from ia import preguntar
from validar import validar
from detector import RUTA_DATOS, cargar_eventos, detectar

MAX_INTENTOS = 3
CARPETA_SALIDA = Path("reglas/generadas")

DESCRIPCION_POR_DEFECTO = (
    "El atacante, desde PowerShell, usa rundll32.exe para llamar a la función MiniDump "
    "de comsvcs.dll y volcar a disco la memoria del proceso lsass.exe, con el fin de "
    "extraer después las credenciales."
)

INSTRUCCIONES = """Eres un ingeniero de detección experto en reglas Sigma.
A partir de la descripción de un ataque en Windows, escribe UNA regla Sigma que lo detecte.

Requisitos obligatorios:
- Responde solo con el YAML de la regla: sin explicaciones y sin bloques de Markdown.
- La telemetría disponible es Sysmon, así que usa un logsource con product: windows y la
  category de Sysmon adecuada (por ejemplo process_creation), con sus nombres de campo.
- Incluye en tags la táctica y al menos una técnica real de MITRE ATT&CK, con el formato
  attack.credential-access y attack.t1003.001. Usa la versión actual de ATT&CK.
- Incluye title, id (un UUID), status, description, author, date, logsource, detection,
  falsepositives y level.
- La detección debe ser lo bastante concreta para no saltar con actividad normal."""

# Ejemplo de regla correcta (few-shot) de una técnica que no está entre los casos medidos:
# enseña el formato, los modificadores y cómo se escribe 'condition' sin dar la respuesta
EJEMPLO = """

Ejemplo de regla correcta para otro ataque (descarga de un archivo con certutil):

title: Descarga de un archivo con certutil
id: 5f3c1b8e-2d4a-4c6b-9e7f-1a2b3c4d5e6f
status: experimental
description: Detecta certutil.exe descargando un archivo de una URL, técnica usada para traer herramientas al equipo.
author: Detection Engineering
date: 2026-10-27
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    product: windows
    category: process_creation
detection:
    seleccion:
        Image|endswith: '\\certutil.exe'
        CommandLine|contains|all:
            - 'urlcache'
            - 'http'
    filtro_legitimo:
        ParentImage|endswith: '\\msiexec.exe'
    condition: seleccion and not filtro_legitimo
falsepositives:
    - Administradores que usan certutil para descargar certificados
level: high"""


def instrucciones():
    return INSTRUCCIONES + (EJEMPLO if CON_EJEMPLO else "")


def limpiar(texto):
    """Quita los bloques de Markdown (```yaml ... ```) si el modelo los ha puesto."""
    bloque = re.search(r"```(?:ya?ml)?\s*\n(.*?)```", texto, re.DOTALL)
    return (bloque.group(1) if bloque else texto).strip() + "\n"


def generar(descripcion):
    """Pide una regla al modelo y la corrige con él hasta que pase el validador.

    Devuelve el texto de la regla válida (o None) y la lista de intentos.
    """
    conversacion = [("user", descripcion)]
    intentos = []
    for numero in range(1, MAX_INTENTOS + 1):
        respuesta, datos = preguntar(instrucciones(), conversacion)
        regla = limpiar(respuesta)
        resultado = validar(regla)
        intentos.append({**datos, "resultado": resultado})
        print(f"Intento {numero}: {datos['segundos']} s, "
              f"{datos['tokens_razonamiento']} tokens de razonamiento -> "
              f"{'VÁLIDA' if not resultado['motivo'] else 'ERROR: ' + resultado['motivo']}")
        if not resultado["motivo"]:
            return regla, intentos

        # Bucle de corrección: le devolvemos su regla y el error para que la arregle
        for d in resultado["detalles"]:
            print("    -", d)
        conversacion += [
            ("model", respuesta),
            ("user", "La regla no pasa el validador. Motivo: " + resultado["motivo"] + "\n"
                     + "\n".join("- " + d for d in resultado["detalles"])
                     + "\nCorrígela y responde de nuevo solo con el YAML."),
        ]
    return None, intentos


if __name__ == "__main__":
    descripcion = sys.argv[1] if len(sys.argv) > 1 else DESCRIPCION_POR_DEFECTO
    print("Descripción:", descripcion, "\n")

    regla, intentos = generar(descripcion)
    if regla is None:
        print(f"\nDESCARTADA: ninguna regla válida en {MAX_INTENTOS} intentos.")
        sys.exit(1)

    CARPETA_SALIDA.mkdir(parents=True, exist_ok=True)
    ruta = CARPETA_SALIDA / f"regla_{datetime.now():%Y%m%d_%H%M%S}.yml"
    ruta.write_text(regla, encoding="utf-8")
    resultado = intentos[-1]["resultado"]
    print(f"\nRegla guardada en {ruta}")
    print("Técnicas ATT&CK:", ", ".join(resultado["tecnicas"]))
    for a in resultado["avisos"]:
        print("  AVISO:", a)

    con, total = cargar_eventos(RUTA_DATOS)
    alertas = detectar(regla, con)
    print(f"\nEventos revisados: {total}")
    print(f"Alertas: {len(alertas)}")
    for a in alertas:
        print("  ->", a["TimeCreated"], "|", a["CommandLine"])
