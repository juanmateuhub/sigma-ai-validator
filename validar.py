import sys
from sigma.collection import SigmaCollection
from sigma.validation import SigmaValidator
from sigma.validators.core import validators
from detector import crear_backend


def validar(texto):
    """Valida una regla Sigma en tres niveles.

    Devuelve un diccionario: 'motivo' es None si la regla vale; si no, explica por qué
    se descarta y 'detalles' lo concreta. 'avisos' y 'tecnicas' solo se rellenan si vale.
    """
    resultado = {"motivo": None, "detalles": [], "avisos": [], "tecnicas": []}

    # Nivel 1: ¿se puede leer y traducir la regla?
    try:
        crear_backend().convert(SigmaCollection.from_yaml(texto))
    except Exception as error:
        resultado.update(motivo="la regla no se puede leer o traducir.", detalles=[str(error)])
        return resultado

    # A partir de aquí trabajamos sobre una copia limpia
    reglas = SigmaCollection.from_yaml(texto)

    # Nivel 2: requisitos de este proyecto -> mapeo ATT&CK presente y real
    tecnicas = [t for r in reglas for t in r.tags if t.namespace == "attack" and t.name.startswith("t")]
    if not tecnicas:
        resultado.update(motivo="la regla no indica ninguna técnica ATT&CK.",
                         detalles=["Añade una etiqueta como attack.t1003.001"])
        return resultado
    problemas_attack = SigmaValidator([validators["attacktag"]]).validate_rules(reglas)
    if problemas_attack:
        resultado.update(motivo="el mapeo a ATT&CK no es válido.",
                         detalles=[p.description for p in problemas_attack])
        return resultado

    # Nivel 3: buenas prácticas generales de Sigma (solo avisan)
    comprobaciones = [v for nombre, v in validators.items() if nombre not in ("attacktag", "d3_fendtag")]
    avisos = SigmaValidator(comprobaciones).validate_rules(reglas)
    resultado["avisos"] = [f"[{a.severity.name}] {a.description}" for a in avisos]
    resultado["tecnicas"] = [t.name.upper() for t in tecnicas]
    return resultado


if __name__ == "__main__":
    ruta = sys.argv[1]
    with open(ruta, encoding="utf-8") as f:
        resultado = validar(f.read())

    if resultado["motivo"]:
        print(f"ERROR: {resultado['motivo']}")
        for d in resultado["detalles"]:
            print("  -", d)
        sys.exit(1)

    if resultado["avisos"]:
        print(f"AVISO: la regla es válida, pero tiene {len(resultado['avisos'])} detalle(s) mejorable(s):")
        for a in resultado["avisos"]:
            print("  -", a)
    else:
        print("OK: la regla es válida y sigue las buenas prácticas.")
    print("Técnicas ATT&CK:", ", ".join(resultado["tecnicas"]))
