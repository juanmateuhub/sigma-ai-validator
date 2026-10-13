import json

RUTA = "datos/psh_lsass_memory_dump_comsvcs_2020-10-18T19500924.json"

with open(RUTA, encoding="utf-8") as f:
    for linea in f:
        e = json.loads(linea)
        if e["Channel"] == "Microsoft-Windows-Sysmon/Operational" and e["EventID"] == 1:
            print("Programa abierto:", e["Image"])
            print("Quién lo abrió:  ", e["ParentImage"])
            print("Línea de órdenes:", e["CommandLine"])