import json
import sqlite3
from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqliteBackend
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import AddConditionTransformation

RUTA_DATOS = "datos/psh_lsass_memory_dump_comsvcs_2020-10-18T19500924.json"
RUTA_REGLA = "reglas/lsass_comsvcs.yml"

# El pipeline de Sysmon añade EventID=1, pero no el canal: en otros registros (System)
# también hay eventos con EventID 1. Esta etapa exige además que vengan de Sysmon.
canal_sysmon = ProcessingPipeline(
    name="Canal de Sysmon",
    priority=20,
    items=[ProcessingItem(
        identifier="canal_sysmon",
        transformation=AddConditionTransformation({"Channel": "Microsoft-Windows-Sysmon/Operational"}),
        rule_conditions=[LogsourceCondition(product="windows", service="sysmon")],
    )],
)


def crear_backend():
    """Backend SQLite con el pipeline de Sysmon y el filtro de canal."""
    return sqliteBackend(processing_pipeline=sysmon_pipeline() + canal_sysmon)


def a_sqlite(valor):
    """SQLite solo guarda valores simples: las listas y diccionarios se guardan como texto JSON."""
    return json.dumps(valor, ensure_ascii=False) if isinstance(valor, (list, dict)) else valor


def cargar_eventos(ruta):
    """Carga un dataset JSON Lines en una tabla "logs" de SQLite en memoria.

    Devuelve la conexión y el número de eventos cargados.
    """
    # Leer las fichas, con los nombres de campo en minúsculas
    with open(ruta, encoding="utf-8") as f:
        # Algunos datasets tienen líneas en blanco entre eventos
        eventos = [{campo.lower(): valor for campo, valor in json.loads(linea).items()}
                   for linea in f if linea.strip()]

    # Montar la tabla "logs" con una columna por cada campo que aparezca
    columnas = sorted({campo for e in eventos for campo in e})
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.execute("CREATE TABLE logs (" + ", ".join('"' + c + '"' for c in columnas) + ")")
    marcadores = ", ".join("?" for _ in columnas)
    con.executemany(f"INSERT INTO logs VALUES ({marcadores})", [[a_sqlite(e.get(c)) for c in columnas] for e in eventos])
    return con, len(eventos)


def detectar(texto_regla, con):
    """Traduce la regla a SQL, la ejecuta sobre la tabla y devuelve las alertas."""
    reglas = SigmaCollection.from_yaml(texto_regla)
    consulta = crear_backend().convert(reglas)[0]
    try:
        return con.execute(consulta).fetchall()
    except sqlite3.OperationalError as error:
        # Si ningún evento del dataset tiene ese campo, la tabla no tiene la columna:
        # como en un SIEM, la regla simplemente no coincide con nada
        if "no such column" in str(error):
            return []
        raise


if __name__ == "__main__":
    con, total = cargar_eventos(RUTA_DATOS)
    with open(RUTA_REGLA, encoding="utf-8") as f:
        alertas = detectar(f.read(), con)

    print(f"Eventos revisados: {total}")
    print(f"Alertas: {len(alertas)}")
    for a in alertas:
        print("  ->", a["TimeCreated"], "|", a["CommandLine"])
