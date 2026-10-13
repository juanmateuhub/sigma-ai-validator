import json
import sqlite3
from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqliteBackend
from sigma.pipelines.sysmon import sysmon_pipeline

RUTA_DATOS = "datos/psh_lsass_memory_dump_comsvcs_2020-10-18T19500924.json"
RUTA_REGLA = "reglas/lsass_comsvcs.yml"

# 1. Leer las fichas, con los nombres de campo en minúsculas
with open(RUTA_DATOS, encoding="utf-8") as f:
    eventos = [{campo.lower(): valor for campo, valor in json.loads(linea).items()} for linea in f]

# 2. Montar la tabla "logs" con una columna por cada campo que aparezca
columnas = sorted({campo for e in eventos for campo in e})
con = sqlite3.connect(":memory:")
con.row_factory = sqlite3.Row
con.execute("CREATE TABLE logs (" + ", ".join('"' + c + '"' for c in columnas) + ")")
marcadores = ", ".join("?" for _ in columnas)
con.executemany(f"INSERT INTO logs VALUES ({marcadores})", [[e.get(c) for c in columnas] for e in eventos])

# 3. Traducir la regla a SQL y ejecutarla sobre la tabla
with open(RUTA_REGLA, encoding="utf-8") as f:
    reglas = SigmaCollection.from_yaml(f.read())
consulta = sqliteBackend(processing_pipeline=sysmon_pipeline()).convert(reglas)[0]
alertas = con.execute(consulta).fetchall()

# 4. Informar
print(f"Eventos revisados: {len(eventos)}")
print(f"Alertas: {len(alertas)}")
for a in alertas:
    print("  ->", a["TimeCreated"], "|", a["CommandLine"])