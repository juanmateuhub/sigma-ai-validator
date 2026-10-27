import json
from collections import defaultdict
from pathlib import Path

# Junta todos los resultados de metricas.py en tablas por modelo y técnica.
# Si un modelo se ha medido varias veces con el mismo prompt, vale la última medición.
# Una regla "detecta" si alerta en al menos un evento del ataque: una cadena de procesos
# (cmd.exe -> schtasks.exe) se considera detectada aunque la regla solo marque uno.
CARPETA_RESULTADOS = Path("resultados")


def cargar_ultimas():
    ultimas = {}
    for ruta in sorted(CARPETA_RESULTADOS.glob("metricas_*.json")):
        filas = json.loads(ruta.read_text(encoding="utf-8"))
        # Las mediciones antiguas (solo T1003.001, sin el campo con_ejemplo) no se comparan
        if not filas or "con_ejemplo" not in filas[0]:
            continue
        ultimas[(filas[0]["modelo"], filas[0]["con_ejemplo"])] = filas
    return ultimas


def buena(fila):
    """Regla válida que detecta el ataque y no da ningún falso positivo."""
    return fila["valida"] and fila["detectados"] > 0 and fila["falsos_positivos"] == 0


def porcentaje(parte, total):
    return f"{parte}/{total} ({100 * parte / total:.0f} %)" if total else "-"


def nombre_prompt(ejemplo):
    return "con ejemplo" if ejemplo else "sin ejemplo"


if __name__ == "__main__":
    ultimas = cargar_ultimas()

    print("| Modelo | Prompt | Reglas | Válidas | Detectan el ataque | Detectan sin FP | Segundos por regla | Errores de la API |")
    print("|---|---|---|---|---|---|---|---|")
    for (modelo, ejemplo), todas in ultimas.items():
        # Las peticiones que fallaron en la API (cuota, 500) no dicen nada del modelo
        filas = [f for f in todas if "error_api" not in f]
        validas = [f for f in filas if f["valida"]]
        detectan = [f for f in validas if f["detectados"] > 0]
        segundos = sum(f["segundos"] for f in filas) / max(len(filas), 1)
        print(f"| {modelo} | {nombre_prompt(ejemplo)} | {len(filas)} | "
              f"{porcentaje(len(validas), len(filas))} | {porcentaje(len(detectan), len(filas))} | "
              f"{porcentaje(sum(buena(f) for f in filas), len(filas))} | {segundos:.0f} | "
              f"{len(todas) - len(filas)} |")

    # Detalle: reglas que detectan el ataque sin falsos positivos, por técnica
    tecnicas = sorted({f["tecnica"] for filas in ultimas.values() for f in filas})
    print("\n| Modelo | Prompt | " + " | ".join(tecnicas) + " |")
    print("|---|---|" + "---|" * len(tecnicas))
    for (modelo, ejemplo), todas in ultimas.items():
        por_tecnica = defaultdict(list)
        for f in todas:
            if "error_api" not in f:
                por_tecnica[f["tecnica"]].append(f)
        celdas = [f"{sum(buena(f) for f in por_tecnica[t])}/{len(por_tecnica[t])}" for t in tecnicas]
        print(f"| {modelo} | {nombre_prompt(ejemplo)} | " + " | ".join(celdas) + " |")

    # Motivos de descarte más frecuentes
    motivos = defaultdict(int)
    for todas in ultimas.values():
        for f in todas:
            if not f["valida"] and "error_api" not in f:
                motivos[f["motivo"]] += 1
    print("\n| Motivo de descarte (tras 3 intentos) | Reglas |")
    print("|---|---|")
    for motivo, n in sorted(motivos.items(), key=lambda m: -m[1]):
        print(f"| {motivo} | {n} |")
