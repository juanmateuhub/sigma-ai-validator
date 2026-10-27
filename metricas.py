import json
from datetime import datetime
from pathlib import Path
from detector import cargar_eventos, detectar
from generar import generar
from config import MODELO

# Windows no admite ":" en nombres de archivo (qwen2.5-coder:7b)
MODELO_ARCHIVO = MODELO.replace(":", "-")

REGLAS_POR_CASO = 5
CARPETA_DATOS = Path("datos")
CARPETA_REGLAS = Path("reglas/generadas")
CARPETA_RESULTADOS = Path("resultados")

# Cada caso: la técnica, la descripción que recibe la IA, el dataset con el ataque y una
# regla de referencia escrita a mano que marca qué eventos son el ataque de verdad.
CASOS = [
    {
        "tecnica": "T1003.001",
        "descripcion": (
            "El atacante, desde PowerShell, usa rundll32.exe para llamar a la función MiniDump "
            "de comsvcs.dll y volcar a disco la memoria del proceso lsass.exe, con el fin de "
            "extraer después las credenciales."
        ),
        "dataset": "psh_lsass_memory_dump_comsvcs_*.json",
        "referencia": "reglas/lsass_comsvcs.yml",
    },
]

# Controles negativos: datasets de otras técnicas, donde la regla no debería saltar
NEGATIVOS = [
    "psh_python_webserver_*.json",
    "cmd_seatbelt_group_user_*.json",
    "cmd_mshta_vbscript_execute_psh_*.json",
    "schtask_create_*.json",
    "empire_persistence_registry_modification_run_keys_standard_user_*.json",
]


def buscar_dataset(patron):
    return next(CARPETA_DATOS.glob(patron))


def evaluar(regla, con_ataque, eventos_ataque, negativos):
    """Cuenta detecciones reales y falsos positivos de una regla válida."""
    alertas = {tuple(a) for a in detectar(regla, con_ataque)}
    falsos = len(alertas - eventos_ataque)
    por_negativo = {}
    for nombre, con in negativos.items():
        por_negativo[nombre] = len(detectar(regla, con))
        falsos += por_negativo[nombre]
    return {
        "detectados": len(alertas & eventos_ataque),
        "ataques": len(eventos_ataque),
        "falsos_positivos": falsos,
        "falsos_en_dataset_ataque": len(alertas - eventos_ataque),
        "falsos_por_negativo": por_negativo,
    }


if __name__ == "__main__":
    print("Cargando controles negativos...")
    negativos = {}
    for patron in NEGATIVOS:
        ruta = buscar_dataset(patron)
        negativos[ruta.stem], total = cargar_eventos(ruta)
        print(f"  {ruta.stem}: {total} eventos")

    fecha = datetime.now()
    resultados = []
    for caso in CASOS:
        con_ataque, _ = cargar_eventos(buscar_dataset(caso["dataset"]))
        with open(caso["referencia"], encoding="utf-8") as f:
            eventos_ataque = {tuple(a) for a in detectar(f.read(), con_ataque)}
        carpeta = CARPETA_REGLAS / caso["tecnica"]
        carpeta.mkdir(parents=True, exist_ok=True)

        for numero in range(1, REGLAS_POR_CASO + 1):
            print(f"\n=== {caso['tecnica']} - regla {numero}/{REGLAS_POR_CASO} ===")
            fila = {"tecnica": caso["tecnica"], "modelo": MODELO, "numero": numero}
            try:
                regla, intentos = generar(caso["descripcion"])
            except Exception as error:
                # Si la API falla incluso tras reintentar, se anota y se sigue con la siguiente
                print("  Error de la API:", str(error).splitlines()[0][:100])
                fila.update(valida=False, error_api=str(error)[:300], intentos=0)
                resultados.append(fila)
                continue

            fila.update(
                valida=regla is not None,
                intentos=len(intentos),
                segundos=round(sum(i["segundos"] for i in intentos), 1),
                tokens=sum(i["tokens_pregunta"] + i["tokens_razonamiento"] + i["tokens_respuesta"]
                           for i in intentos),
                motivo=intentos[-1]["resultado"]["motivo"],
            )
            if regla is not None:
                ruta = carpeta / f"{MODELO_ARCHIVO}_{fecha:%Y%m%d_%H%M%S}_{numero}.yml"
                ruta.write_text(regla, encoding="utf-8")
                fila["regla"] = str(ruta)
                fila["tecnicas_regla"] = intentos[-1]["resultado"]["tecnicas"]
                fila.update(evaluar(regla, con_ataque, eventos_ataque, negativos))
                print(f"  Detecta {fila['detectados']}/{fila['ataques']} | "
                      f"falsos positivos: {fila['falsos_positivos']}")
            resultados.append(fila)

    CARPETA_RESULTADOS.mkdir(exist_ok=True)
    salida = CARPETA_RESULTADOS / f"metricas_{MODELO_ARCHIVO}_{fecha:%Y%m%d_%H%M%S}.json"
    salida.write_text(json.dumps(resultados, indent=2, ensure_ascii=False), encoding="utf-8")

    # Resumen por técnica
    print("\n| Técnica | Modelo | Válidas | Detectan | Sin FP | Intentos medios | Segundos medios |")
    print("|---|---|---|---|---|---|---|")
    for caso in CASOS:
        filas = [r for r in resultados if r["tecnica"] == caso["tecnica"]]
        validas = [r for r in filas if r["valida"]]
        detectan = [r for r in validas if r["detectados"] == r["ataques"]]
        sin_fp = [r for r in detectan if r["falsos_positivos"] == 0]
        con_datos = [r for r in filas if r["intentos"]]
        intentos = sum(r["intentos"] for r in con_datos) / max(len(con_datos), 1)
        segundos = sum(r["segundos"] for r in con_datos) / max(len(con_datos), 1)
        print(f"| {caso['tecnica']} | {MODELO} | {len(validas)}/{len(filas)} | {len(detectan)}/{len(filas)} | "
              f"{len(sin_fp)}/{len(filas)} | {intentos:.1f} | {segundos:.1f} |")
    print(f"\nResultados guardados en {salida}")
