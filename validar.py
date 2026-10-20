import sys
from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqliteBackend
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.validation import SigmaValidator
from sigma.validators.core import validators


def descartar(motivo, detalles):
    print(f"ERROR: {motivo}")
    for d in detalles:
        print("  -", d)
    sys.exit(1)


ruta = sys.argv[1]
with open(ruta, encoding="utf-8") as f:
    texto = f.read()

# Nivel 1: ¿se puede leer y traducir la regla?
try:
    sqliteBackend(processing_pipeline=sysmon_pipeline()).convert(SigmaCollection.from_yaml(texto))
except Exception as error:
    descartar("la regla no se puede leer o traducir.", [error])

# A partir de aquí trabajamos sobre una copia limpia
reglas = SigmaCollection.from_yaml(texto)

# Nivel 2: requisitos de este proyecto -> mapeo ATT&CK presente y real
tecnicas = [t for r in reglas for t in r.tags if t.namespace == "attack" and t.name.startswith("t")]
if not tecnicas:
    descartar("la regla no indica ninguna técnica ATT&CK.", ["Añade una etiqueta como attack.t1003.001"])
problemas_attack = SigmaValidator([validators["attacktag"]]).validate_rules(reglas)
if problemas_attack:
    descartar("el mapeo a ATT&CK no es válido.", [p.description for p in problemas_attack])

# Nivel 3: buenas prácticas generales de Sigma (solo avisan)
comprobaciones = [v for nombre, v in validators.items() if nombre not in ("attacktag", "d3_fendtag")]
avisos = SigmaValidator(comprobaciones).validate_rules(reglas)
if avisos:
    print(f"AVISO: la regla es válida, pero tiene {len(avisos)} detalle(s) mejorable(s):")
    for a in avisos:
        print(f"  - [{a.severity.name}] {a.description}")
else:
    print("OK: la regla es válida y sigue las buenas prácticas.")
print("Técnicas ATT&CK:", ", ".join(t.name.upper() for t in tecnicas))