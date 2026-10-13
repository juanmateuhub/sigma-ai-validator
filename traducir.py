from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqliteBackend
from sigma.pipelines.sysmon import sysmon_pipeline

with open("reglas/lsass_comsvcs.yml", encoding="utf-8") as f:
    reglas = SigmaCollection.from_yaml(f.read())

traductor_generico = sqliteBackend()
traductor_sysmon = sqliteBackend(processing_pipeline=sysmon_pipeline())

print("Sin adaptador:\n", traductor_generico.convert(reglas)[0])
print("\nCon adaptador de Sysmon:\n", traductor_sysmon.convert(reglas)[0])