import sys
import yaml
from sigma.collection import SigmaCollection
from sigma.data import mitre_attack
from sigma.validation import SigmaValidator
from sigma.validators.core import validators
from sigma.pipelines.sysmon.sysmon import sysmon_generic_logsource_eventid_mapping
from sigma.rule import SigmaDetection
from campos_sysmon import CAMPOS_EVENTO, CAMPOS_POR_CATEGORIA
from detector import crear_backend

# Explicación para los errores de 'condition', que pySigma da en términos poco claros
PISTA_CONDICION = ("En Sigma, 'condition' solo combina los NOMBRES de las selecciones definidas "
                   "dentro de detection (por ejemplo: 'selection', 'selection and not filter', "
                   "'1 of selection_*'). Los campos y valores van dentro de cada selección, "
                   "por ejemplo: selection: {Image|endswith: '\\rundll32.exe', CommandLine|contains: 'MiniDump'}.")


def pistas_attack(tecnicas):
    """Explica qué tácticas acepta la versión actual de ATT&CK y a cuál pertenece cada técnica.

    ATT&CK cambia: en la v18, Defense Evasion se dividió en Stealth y Defense Impairment,
    y los modelos siguen escribiendo attack.defense-evasion.
    """
    datos = mitre_attack._load_mitre_attack_data()
    tacticas = sorted(datos["mitre_attack_tactics"].values())
    pistas = [f"Tácticas válidas (ATT&CK {datos['mitre_attack_version']}): {', '.join(tacticas)}"]
    for t in tecnicas:
        codigo = t.name.upper()
        if codigo in datos["mitre_attack_techniques"]:
            pistas.append(f"{codigo} ({datos['mitre_attack_techniques'][codigo]}) pertenece a: "
                          + ", ".join(datos["mitre_attack_techniques_tactics_mapping"].get(codigo, [])))
        else:
            pistas.append(f"{codigo} no existe en ATT&CK {datos['mitre_attack_version']}.")
    return pistas


def campos_usados(regla):
    """Devuelve los nombres de campo que usa la detección (sin repetir y en orden)."""
    campos = []
    pendientes = list(regla.detection.detections.values())
    while pendientes:
        elemento = pendientes.pop(0)
        if isinstance(elemento, SigmaDetection):
            # Una detección puede contener otras detecciones (listas de mapas) o elementos
            pendientes.extend(elemento.detection_items)
        elif elemento.field and elemento.field not in campos:
            campos.append(elemento.field)
    return campos


def validar(texto):
    """Valida una regla Sigma en tres niveles.

    Devuelve un diccionario: 'motivo' es None si la regla vale; si no, explica por qué
    se descarta y 'detalles' lo concreta. 'avisos' y 'tecnicas' solo se rellenan si vale.
    """
    resultado = {"motivo": None, "detalles": [], "avisos": [], "tecnicas": []}

    # Nivel 1: ¿se puede leer y traducir la regla?
    try:
        if isinstance(yaml.safe_load(texto), list):
            # pySigma solo dice "'list' object has no attribute 'get'", que no orienta al modelo
            raise ValueError("La regla es una lista YAML (empieza por '- title:'). "
                             "Debe ser un mapa: quita el '- ' y la sangría de la primera línea.")
        crear_backend().convert(SigmaCollection.from_yaml(texto))
    except Exception as error:
        detalles = [str(error)]
        if "not defined in detections" in str(error) or "Unbalanced parentheses" in str(error):
            detalles.append(PISTA_CONDICION)
        resultado.update(motivo="la regla no se puede leer o traducir.", detalles=detalles)
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
                         detalles=[f"{p.description}: {p.tag}"
                                   for p in problemas_attack] + pistas_attack(tecnicas))
        return resultado

    # Nivel 2 (cont.): los campos deben existir en el evento de Sysmon de esa categoría;
    # si no, la regla traduce bien pero nunca puede coincidir con nada
    avisos_campos = []
    for regla in reglas:
        categoria = regla.logsource.category
        # Sin categoría, el pipeline de Sysmon no filtra por EventID y la regla miraría todos los eventos
        if categoria is None:
            resultado.update(motivo="el logsource no indica la categoría (category).",
                             detalles=["Usa product: windows y una category de Sysmon, "
                                       f"por ejemplo: {', '.join(CAMPOS_POR_CATEGORIA)}"])
            return resultado
        # Una categoría que el pipeline no conoce (p. ej. "registry") no recibe filtro de EventID
        # ni de canal: la regla se aplicaría a cualquier evento
        if categoria not in sysmon_generic_logsource_eventid_mapping:
            resultado.update(motivo=f"la categoría {categoria} no existe en Sysmon.",
                             detalles=["Categorías de Sysmon: "
                                       + ", ".join(sorted(sysmon_generic_logsource_eventid_mapping))])
            return resultado
        if categoria not in CAMPOS_POR_CATEGORIA:
            avisos_campos.append(f"[CAMPOS] No se comprueban los campos de la categoría {categoria!r}.")
            continue
        # El detector pasa los nombres a minúsculas, así que no distinguimos mayúsculas
        validos = CAMPOS_POR_CATEGORIA[categoria]
        permitidos = {c.lower() for c in validos + CAMPOS_EVENTO}
        inexistentes = [c for c in campos_usados(regla) if c.lower() not in permitidos]
        if inexistentes:
            resultado.update(
                motivo=f"la regla usa campos que no existen en la categoría {categoria} de Sysmon.",
                detalles=[f"Campos inexistentes: {', '.join(inexistentes)}",
                          f"Campos disponibles en {categoria}: {', '.join(validos)}"])
            return resultado

    # Nivel 3: buenas prácticas generales de Sigma (solo avisan)
    comprobaciones = [v for nombre, v in validators.items() if nombre not in ("attacktag", "d3_fendtag")]
    avisos = SigmaValidator(comprobaciones).validate_rules(reglas)
    resultado["avisos"] = avisos_campos + [f"[{a.severity.name}] {a.description}" for a in avisos]
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
