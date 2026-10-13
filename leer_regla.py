from sigma.rule import SigmaRule

with open("reglas/lsass_comsvcs.yml", encoding="utf-8") as f:
    regla = SigmaRule.from_yaml(f.read())

print("Título:   ", regla.title)
print("Nivel:    ", regla.level)
print("Etiquetas:", [str(t) for t in regla.tags])