# sigma-ai-validator

**¿Se puede confiar en un LLM para escribir reglas de detección?** Esta herramienta lo mide.

Recibe la descripción de un ataque en lenguaje natural, pide a un modelo de IA una regla
[Sigma](https://github.com/SigmaHQ/sigma) y **no se fía de ella**: la valida, se la devuelve al
modelo con el error concreto hasta que la arregle y, por último, la ejecuta contra registros
reales de ataques en Windows ([OTRF Security Datasets](https://github.com/OTRF/Security-Datasets))
para contar cuántas detectan el ataque y cuántas dan falsos positivos.

```
descripción del ataque
        │
        ▼
   ┌─────────┐   regla Sigma   ┌──────────────────────────────┐
   │   LLM   │ ──────────────► │ Validador (3 niveles)        │
   │ Gemini  │ ◄────────────── │ 1. ¿se lee y se traduce?     │
   │ Ollama  │  error concreto │ 2. ATT&CK real, campos reales│
   └─────────┘ (hasta 3 veces) │ 3. buenas prácticas (aviso)  │
                               └──────────────┬───────────────┘
                                              │ regla válida
                                              ▼
                          ┌────────────────────────────────────────┐
                          │ Detector: Sigma → SQL → SQLite         │
                          │ dataset del ataque  → ¿detecta?        │
                          │ datasets de otras 5 técnicas → ¿FP?    │
                          └────────────────────────────────────────┘
```

## Resultados

Seis técnicas ATT&CK, cada una con su dataset de ataque; los otros cinco datasets hacen de
controles negativos. "Detectan sin FP" = regla válida que alerta en el ataque y en nada más.
Salida de `python resumen.py`:

| Modelo | Prompt | Reglas | Válidas | Detectan el ataque | Detectan sin FP | Segundos por regla | Errores de la API |
|---|---|---|---|---|---|---|---|
| gemini-3.6-flash | con ejemplo | 8 | 8/8 (100 %) | 8/8 (100 %) | 8/8 (100 %) | 37 | 4 |
| qwen2.5-coder:7b | con ejemplo | 30 | 23/30 (77 %) | 3/30 (10 %) | 3/30 (10 %) | 18 | 0 |
| qwen2.5-coder:7b | sin ejemplo | 30 | 18/30 (60 %) | 3/30 (10 %) | 3/30 (10 %) | 15 | 0 |
| qwen3:8b | con ejemplo | 18 | 15/18 (83 %) | 1/18 (6 %) | 1/18 (6 %) | 130 | 0 |
| qwen3:8b | sin ejemplo | 18 | 6/18 (33 %) | 1/18 (6 %) | 0/18 (0 %) | 142 | 0 |

Reglas que detectan sin falsos positivos, por técnica:

| Modelo | Prompt | T1003.001 | T1053.005 | T1082 | T1218.005 | T1547.001 | T1686.003 |
|---|---|---|---|---|---|---|---|
| gemini-3.6-flash | con ejemplo | 2/2 | 2/2 | 0/0 | 2/2 | 1/1 | 1/1 |
| qwen2.5-coder:7b | con ejemplo | 0/5 | 2/5 | 0/5 | 1/5 | 0/5 | 0/5 |
| qwen2.5-coder:7b | sin ejemplo | 0/5 | 0/5 | 1/5 | 2/5 | 0/5 | 0/5 |
| qwen3:8b | con ejemplo | 0/3 | 1/3 | 0/3 | 0/3 | 0/3 | 0/3 |
| qwen3:8b | sin ejemplo | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 |

Motivos de descarte (la regla sigue mal tras 3 intentos):

| Motivo | Reglas |
|---|---|
| la regla no se puede leer o traducir | 22 |
| usa campos que no existen en `process_creation` | 6 |
| el mapeo a ATT&CK no es válido | 4 |
| no indica ninguna técnica ATT&CK | 1 |
| usa campos que no existen en `registry_event` | 1 |

En resumen:

- **Gemini detecta casi siempre; los modelos locales de 7-8B, casi nunca.** Todas las reglas de
  Gemini que llegaron a generarse detectan su ataque sin falsos positivos. Cuatro peticiones
  fallaron por la cuota gratuita o por errores 500, y T1082 se quedó sin ninguna. Los locales
  aciertan entre un 0 % y un 10 %.
- **Validez ≠ detección.** `qwen3:8b` con ejemplo consigue un 83 % de reglas válidas y solo
  una detecta el ataque.
- **El ejemplo del prompt ayuda con el formato, pero contagia la lógica.** Con ejemplo, la
  validez sube (de 60 % a 77 % en `qwen2.5-coder`, de 33 % a 83 % en `qwen3`) y la detección
  no cambia. `qwen3` copia del ejemplo el bloque `filtro_legitimo` y excluye
  `ParentImage: cmd.exe`, que es justo el padre del ataque de Seatbelt (T1082). Sin ejemplo,
  `qwen3` sí detecta T1082 una vez, pero con falsos positivos.

## Qué he aprendido

- **Que una regla sea válida no significa que detecte.** La mayoría de reglas de los modelos
  locales pasan el validador y no detectan nada: usan campos que el evento no tiene
  (`TargetFilename` en `process_creation`), invierten padre e hijo (`ParentImage: lsass.exe`)
  o escriben valores que no coinciden con lo que de verdad registra Sysmon
  (`comsvcs.dll,MiniDump` con coma). Solo se ve probándolas contra datos reales.
- **El bucle de corrección solo funciona si el error se entiende.** Mensajes de pySigma como
  `'list' object has no attribute 'get'` o `Detection 'all' not defined` hacían que el modelo
  repitiera la misma regla tres veces. Con mensajes que explican qué corregir (y la lista de
  campos o tácticas válidas) la tasa de reglas válidas sube claramente.
- **ATT&CK cambia y los modelos no se enteran.** En ATT&CK v18 *Defense Evasion* se dividió en
  *Stealth* y *Defense Impairment*, y T1562.004 pasó a T1686.003. Los modelos siguen escribiendo
  `attack.defense-evasion`; el validador lo detecta y les dice la táctica actual.
- **El filtro de canal importa.** El pipeline de Sysmon de pySigma añade `EventID=1`, pero no
  comprueba el canal: el dataset de Empire tiene eventos con `EventID 1` del canal `System`.
  El detector añade `Channel = 'Microsoft-Windows-Sysmon/Operational'`.
- **Nivel gratuito ≠ banco de pruebas.** Gemini gratis permite 20 peticiones al día por modelo;
  por eso las métricas se hacen sobre todo con modelos locales (Ollama) y Gemini queda como
  referencia con una muestra pequeña.

## Cómo funciona

### Validador (`validar.py`)

| Nivel | Qué comprueba | Si falla |
|---|---|---|
| 1 | La regla se lee y se traduce a SQL (backend SQLite + pipeline Sysmon) | ERROR |
| 2 | Tiene al menos una técnica ATT&CK y existe en la versión actual (validador `attacktag`) | ERROR |
| 2 | El `logsource` indica `category` y todos los campos existen en ese evento de Sysmon (`campos_sysmon.py`) | ERROR |
| 3 | Resto de validadores de pySigma (comodines, duplicados, etc.) | AVISO |

Un ATT&CK inventado descarta la regla: la tabla de resultados se organiza por técnica y una
técnica inexistente es una alucinación.

### Métricas (`metricas.py`)

Cada caso tiene una **regla de referencia escrita a mano** (`reglas/*.yml`) que marca qué eventos
son el ataque real. Para cada regla generada:

- **Detecta**: alerta en al menos un evento del ataque (una cadena `cmd.exe → schtasks.exe` se
  detecta una vez).
- **Falso positivo**: cualquier otra alerta, en el dataset del ataque o en los datasets de las
  otras cinco técnicas, que hacen de controles negativos.

| Técnica | Táctica | Dataset de OTRF | Eventos |
|---|---|---|---|
| T1003.001 LSASS Memory | credential-access | `psh_lsass_memory_dump_comsvcs` | 184 |
| T1218.005 Mshta | stealth | `cmd_mshta_vbscript_execute_psh` | 1 127 |
| T1053.005 Scheduled Task | execution, persistence | `schtask_create` | 1 041 |
| T1547.001 Registry Run Keys | persistence | `empire_persistence_registry_modification_run_keys_standard_user` | 40 569 |
| T1686.003 Windows Host Firewall | defense-impairment | `psh_python_webserver` | 2 395 |
| T1082 System Information Discovery | discovery | `cmd_seatbelt_group_user` | 451 |

Las reglas de referencia se han comprobado en la matriz completa: cada una salta solo en su
propio dataset.

### Proveedores de IA (`ia.py`)

`ia.py` expone una única función, `preguntar(instrucciones, conversacion)`, y elige el módulo
según `PROVEEDOR`:

- `ia_gemini.py`: API de Gemini (`google-genai`), con reintentos ante `429`, `503` y `504`.
- `ia_ollama.py`: modelos locales con [Ollama](https://ollama.com). Activa el razonamiento si
  el modelo lo admite (`qwen3`).

El prompt (`generar.py`) incluye por defecto una regla de ejemplo de otra técnica (descarga con
`certutil`, T1105) que enseña el formato sin dar la respuesta.

## Uso (Windows, PowerShell)

```powershell
git clone https://github.com/juanmateuhub/sigma-ai-validator.git
cd sigma-ai-validator
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt

python descargar.py          # baja los 6 datasets de OTRF a datos\ (unos 90 MB)
```

Con Ollama (local, sin cuotas):

```powershell
winget install Ollama.Ollama
ollama pull qwen2.5-coder:7b
python generar.py           # genera una regla para el volcado de LSASS y la prueba
python generar.py "El atacante usa certutil para descargar un ejecutable"   # otra descripción
python metricas.py           # 6 técnicas x 5 reglas
python resumen.py            # tablas de resultados de todas las mediciones
```

Con Gemini: crea un archivo `.env` con `GEMINI_API_KEY=...` (no se versiona) y:

```powershell
$env:PROVEEDOR = "gemini"; $env:REGLAS_POR_CASO = "2"
python metricas.py
```

| Variable | Para qué | Valor por defecto |
|---|---|---|
| `PROVEEDOR` | `ollama` o `gemini` | `ollama` |
| `MODELO` | modelo concreto | `qwen2.5-coder:7b` / `gemini-3.6-flash` |
| `CON_EJEMPLO` | `0` para quitar la regla de ejemplo del prompt | `1` |
| `REGLAS_POR_CASO` | reglas generadas por técnica | `5` |

Otras herramientas: `python validar.py <regla.yml>` valida una regla y
`python detector.py` ejecuta la regla de LSASS contra su dataset.

## Estructura

```
├── generar.py          descripción → regla Sigma, con bucle de corrección
├── validar.py          validador en tres niveles
├── campos_sysmon.py    campos de cada evento de Sysmon por categoría
├── detector.py         carga un dataset en SQLite y ejecuta la regla traducida
├── metricas.py         N reglas por técnica: validez, detección y falsos positivos
├── resumen.py          tablas de resultados por modelo y técnica
├── ia.py               elige proveedor: ia_gemini.py / ia_ollama.py
├── config.py           proveedor, modelo y opciones
├── descargar.py        datasets de OTRF
├── reglas/             reglas de referencia escritas a mano
│   └── generadas/      reglas generadas por los modelos, por técnica
├── resultados/         resultados de cada medición (JSON)
└── pruebas/            reglas rotas a propósito para probar el validador
```

Los scripts `explorar.py`, `buscar.py`, `leer_regla.py`, `traducir.py`, `hola_ia.py`,
`listar_modelos.py` y `probar_modelos.py` son los pasos de exploración con los que se construyó
el proyecto.

## Limitaciones

- Muestras pequeñas: 5 reglas por técnica con `qwen2.5-coder`, 3 con `qwen3` (unos 2 minutos
  por regla) y 2 con Gemini (cuota gratuita). Los
  resultados indican tendencias, no son una evaluación estadística.
- Un solo dataset de ataque por técnica, todos del mismo laboratorio (OTRF). Los falsos
  positivos se miden contra otros ataques, no contra semanas de actividad normal.
- Solo telemetría de Sysmon; los eventos de Security no se usan todavía.

## Licencia

[MIT](LICENSE). Los datasets son de [OTRF Security Datasets](https://github.com/OTRF/Security-Datasets).
