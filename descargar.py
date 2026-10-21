import io
import zipfile
from pathlib import Path
from urllib.request import urlopen

BASE = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/"
CARPETA = Path("datos")

# Ruta dentro del repositorio de OTRF (táctica/host/nombre.zip)
DATASETS = [
    "credential_access/host/psh_lsass_memory_dump_comsvcs.zip",
    # Controles negativos: técnicas de otras tácticas
    "execution/host/psh_python_webserver.zip",
    "discovery/host/cmd_seatbelt_group_user.zip",
    "defense_evasion/host/cmd_mshta_vbscript_execute_psh.zip",
    "lateral_movement/host/schtask_create.zip",
    "persistence/host/empire_persistence_registry_modification_run_keys_standard_user.zip",
]

CARPETA.mkdir(exist_ok=True)
for ruta in DATASETS:
    with urlopen(BASE + ruta) as respuesta:
        comprimido = zipfile.ZipFile(io.BytesIO(respuesta.read()))
    for nombre in comprimido.namelist():
        # Solo los .json y sin subcarpetas, para que el zip no pueda escribir fuera de datos/
        if nombre.endswith(".json"):
            destino = CARPETA / Path(nombre).name
            destino.write_bytes(comprimido.read(nombre))
            print("Descargado:", destino)
