import sys
from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqliteBackend
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.validation import SigmaValidator
from sigma.validators.core import validators

ruta = sys.argv[1]
with open(ruta, encoding="utf-8") as f:
    texto = f.read()

# Nivel 1: ¿se puede leer y traducir la regla?
try:
    sqliteBackend(processing_pipeline=sysmon_pipeline()).convert(SigmaCollection.from_yaml(texto))
except Exception as error:
    print("ERROR: la regla no se puede leer o traducir.")
    print("  -", error)
    sys.exit(1)

# Nivel 2: ¿sigue las buenas prácticas de Sigma? (sobre una copia limpia)
reglas = SigmaCollection.from_yaml(texto)
comprobaciones = [v for nombre, v in validators.items() if nombre != "d3_fendtag"]
avisos = SigmaValidator(comprobaciones).validate_rules(reglas)
if avisos:
    print(f"AVISO: la regla funciona, pero tiene {len(avisos)} problema(s):")
    for a in avisos:
        print(f"  - [{a.severity.name}] {a.description}")
else:
    print("OK: la regla es válida y sigue las buenas prácticas.")