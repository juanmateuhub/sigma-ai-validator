import json
from collections import Counter

RUTA = "datos/psh_lsass_memory_dump_comsvcs_2020-10-18T19500924.json"

with open(RUTA, encoding="utf-8") as f:
    eventos = [json.loads(linea) for linea in f]

print("Total de eventos:", len(eventos))
for (canal, id_evento), n in Counter((e["Channel"], e["EventID"]) for e in eventos).most_common():
    print(f"{n:4}  {canal}  ->  EventID {id_evento}")