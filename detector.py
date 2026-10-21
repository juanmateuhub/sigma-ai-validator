import json
import sqlite3
from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqliteBackend
from sigma.pipelines.sysmon import sysmon_pipeline

RUTA_DATOS = "datos/psh_lsass_memory_dump_comsvcs_2020-10-18T19500924.json"
RUTA_REGLA = "reglas/lsass_comsvcs.yml"


def cargar_eventos(ruta):
    """Carga un dataset JSON Lines en una tabla "logs" de SQLite en memoria.

    Devuelve la conexión y el número de eventos cargados.
    """
    # Leer las fichas, con los nombres de campo en minúsculas
    with open(ruta, encoding="utf-8") as f:
        eventos = [{campo.lower(): valor for campo, valor in json.loads(linea).items()} for linea in f]

    # Montar la tabla "logs" con una columna por cada campo que aparezca
    columnas = sorted({campo for e in eventos for campo in e})
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.execute("CREATE TABLE logs (" + ", ".join('"' + c + '"' for c in columnas) + ")")
    marcadores = ", ".join("?" for _ in columnas)
    con.executemany(f"INSERT INTO logs VALUES ({marcadores})", [[e.get(c) for c in columnas] for e in eventos])
    return con, len(eventos)


def detectar(texto_regla, con):
    """Traduce la regla a SQL, la ejecuta sobre la tabla y devuelve las alertas."""
    reglas = SigmaCollection.from_yaml(texto_regla)
    consulta = sqliteBackend(processing_pipeline=sysmon_pipeline()).convert(reglas)[0]
    return con.execute(consulta).fetchall()


if __name__ == "__main__":
    con, total = cargar_eventos(RUTA_DATOS)
    with open(RUTA_REGLA, encoding="utf-8") as f:
        alertas = detectar(f.read(), con)

    print(f"Eventos revisados: {total}")
    print(f"Alertas: {len(alertas)}")
    for a in alertas:
        print("  ->", a["TimeCreated"], "|", a["CommandLine"])
