# Campos que Sysmon escribe en cada tipo de evento, por categoría de logsource de Sigma.
# Fuente: esquema de Sysmon (sysmon -s). Solo las categorías que más usan las reglas;
# una categoría que no esté aquí no se puede comprobar y el validador solo avisa.

# Campos del registro de Windows que tiene cualquier evento, sea de la categoría que sea
CAMPOS_EVENTO = ["EventID", "Channel"]

_COMUNES = ["RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "User"]

CAMPOS_POR_CATEGORIA = {
    # EventID 1
    "process_creation": _COMUNES + [
        "FileVersion", "Description", "Product", "Company", "OriginalFileName", "CommandLine",
        "CurrentDirectory", "LogonGuid", "LogonId", "TerminalSessionId", "IntegrityLevel",
        "Hashes", "ParentProcessGuid", "ParentProcessId", "ParentImage", "ParentCommandLine",
        "ParentUser",
    ],
    # EventID 3
    "network_connection": _COMUNES + [
        "Protocol", "Initiated", "SourceIsIpv6", "SourceIp", "SourceHostname", "SourcePort",
        "SourcePortName", "DestinationIsIpv6", "DestinationIp", "DestinationHostname",
        "DestinationPort", "DestinationPortName",
    ],
    # EventID 7
    "image_load": _COMUNES + [
        "ImageLoaded", "FileVersion", "Description", "Product", "Company", "OriginalFileName",
        "Hashes", "Signed", "Signature", "SignatureStatus",
    ],
    # EventID 10: aquí no hay Image, sino SourceImage y TargetImage
    "process_access": [
        "RuleName", "UtcTime", "SourceProcessGUID", "SourceProcessId", "SourceThreadId",
        "SourceImage", "TargetProcessGUID", "TargetProcessId", "TargetImage", "GrantedAccess",
        "CallTrace", "SourceUser", "TargetUser",
    ],
    # EventID 11
    "file_event": _COMUNES + ["TargetFilename", "CreationUtcTime"],
    # EventID 12, 13 y 14
    "registry_event": _COMUNES + ["EventType", "TargetObject", "Details", "NewName"],
    "registry_add": _COMUNES + ["EventType", "TargetObject"],
    "registry_delete": _COMUNES + ["EventType", "TargetObject"],
    "registry_set": _COMUNES + ["EventType", "TargetObject", "Details"],
    "registry_rename": _COMUNES + ["EventType", "TargetObject", "NewName"],
    # EventID 22
    "dns_query": _COMUNES + ["QueryName", "QueryStatus", "QueryResults"],
}
