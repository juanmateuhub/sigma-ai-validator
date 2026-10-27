# CLAUDE.md — Generador y validador de reglas de detección con IA

Este archivo da a Claude Code el contexto completo del proyecto: qué es, cómo se ha construido hasta ahora, qué decisiones se han tomado y por dónde seguir.

## Cómo trabajar con el autor (importante)

- El autor es Juan Mateu Museros, estudiante de último curso de Ingeniería Informática (UJI). Quiere **aprender** con este proyecto, no que se lo hagan.
- **No escribas el proyecto entero de golpe.** Avanza en pasos pequeños: explica cada concepto con una analogía sencilla, da el código y los comandos exactos, explica qué hace cada parte y qué salida se espera, y espera a que Juan lo ejecute y confirme antes de seguir.
- Responde siempre en **español**, con tono profesional y claro.
- Juan trabaja en **Windows con PowerShell**. Nada de Linux ni comandos de bash. Rutas con `\`.
- Al terminar cada paso que funcione, propón un `commit` con un mensaje descriptivo ("guardar partida").
- Cuando haya una decisión de diseño, explica las alternativas y sus ventajas e inconvenientes, y deja que Juan decida (hasta ahora, una recomendación razonada ha funcionado bien).
- Cuando algo falle, diagnostica de forma sistemática con lo que ya está demostrado. Evita encadenar pruebas de un solo ajuste a ciegas.

## Objetivo del proyecto

Herramienta en Python que:

1. Recibe la descripción en lenguaje natural de un ataque.
2. Pide a un LLM que escriba una regla de detección en formato **Sigma**.
3. **No se fía del LLM**: valida la regla (sintaxis, traducción y mapeo a MITRE ATT&CK obligatorio).
4. La prueba contra registros reales de ataques en Windows (**OTRF Security Datasets**).
5. Mide detecciones y falsos positivos.
6. Genera una tabla de resultados por técnica ATT&CK (y, como extra, una comparativa entre modelos de IA).

Es un proyecto de portfolio para GitHub (`github.com/juanmateuhub`), orientado a puestos de Detection Engineer / analista SOC.

## Entorno

- Carpeta: `C:\Users\Usuario\proyectos\sigma-ai-validator`
- Python 3.12, entorno virtual en `.venv` (activar con `.venv\Scripts\Activate.ps1`; la política de ejecución ya está en `RemoteSigned` para el usuario).
- Paquetes instalados: `pysigma`, `pysigma-backend-sqlite`, `pysigma-pipeline-sysmon`, `google-genai`, `python-dotenv`. Conviene crear un `requirements.txt` en algún momento.
- `.gitignore`: `.venv/`, `datos/`, `.env`.
- Secretos: la clave de Gemini está en `.env` como `GEMINI_API_KEY=...`. **Nunca** debe escribirse en el código ni subirse a Git.
- Hardware: NVIDIA RTX 3060 Laptop con **6 GB** de VRAM. Un modelo de 7-8B en Q4 cabe casi entero (qwen2.5-coder:7b: 79 % GPU / 21 % CPU con contexto de 8192).
- Ollama 0.40.11 instalado con winget (`%LOCALAPPDATA%\Programs\Ollama\ollama.exe`, servidor en `http://localhost:11434`). Paquete Python `ollama` en el `.venv`.

## Estructura actual

```
sigma-ai-validator/
├── .gitignore
├── .env                      # NO versionado (clave de Gemini)
├── config.py                 # MODELO = "gemini-3.8-flash"
├── datos/                    # NO versionado; datasets descargados de OTRF
│   └── psh_lsass_memory_dump_comsvcs_2020-10-18T19500924.json
├── reglas/
│   └── lsass_comsvcs.yml     # regla escrita a mano (T1003.001)
├── pruebas/
│   ├── regla_rota.yml              # caso de prueba nivel 1 (condición "selecion")
│   └── regla_attack_inventado.yml  # caso de prueba nivel 2 (attack.t9999)
├── explorar.py               # cuenta eventos por canal y EventID
├── buscar.py                 # muestra los eventos Sysmon EventID 1
├── leer_regla.py             # carga una regla con SigmaRule.from_yaml
├── traducir.py               # muestra la regla traducida a SQL (con y sin pipeline Sysmon)
├── detector.py               # carga el JSON en SQLite en memoria y ejecuta la regla traducida
├── validar.py                # validador en tres niveles (ver abajo)
├── listar_modelos.py         # lista modelos Gemini "flash" con generateContent
├── hola_ia.py                # primera llamada a Gemini con timeout, cronómetro y tokens
├── probar_modelos.py         # prueba varios modelos Gemini de golpe
├── ia.py                     # preguntar(instrucciones, conversacion): llamada al modelo con reintentos
├── generar.py                # descripción -> regla Sigma con bucle de corrección
├── descargar.py              # baja los datasets de OTRF a datos/
├── metricas.py               # N reglas por técnica: válidas, detección real y falsos positivos
└── reglas/generadas/         # reglas generadas por la IA (por técnica en metricas.py)
```

## Plan por fases y estado

### Fase 0 — Entorno. HECHA
Python, Git, entorno virtual, pySigma.

### Fase 1 — Explorar un ataque real. HECHA
- Dataset: `datasets/atomic/windows/credential_access/host/psh_lsass_memory_dump_comsvcs.zip` del repositorio `OTRF/Security-Datasets` (rama `master`). Formato: **JSON Lines** (un evento por línea), no `.evtx`; por eso `python-evtx` no ha hecho falta.
- 184 eventos (Sysmon y Security). El ataque es un único evento Sysmon EventID 1: `rundll32.exe C:\windows\System32\comsvcs.dll MiniDump 756 ...\lsass-comsvcs.dmp full`, lanzado desde `powershell.exe`. También hay 68 eventos Sysmon EventID 10 (acceso a memoria de procesos), no aprovechados todavía.
- Regla manual `reglas/lsass_comsvcs.yml`: `logsource` `windows/process_creation`; `Image|endswith: '\rundll32.exe'` y `CommandLine|contains|all: [comsvcs, MiniDump]`; tags `attack.credential-access` y `attack.t1003.001`; `level: high`.

### Fase 2 — Detector. HECHA
- `detector.py`: lee el JSON, pasa **los nombres de campo a minúsculas** (el dataset tiene `ProcessId` y `ProcessID`, que chocan en SQLite porque los nombres de columna no distinguen mayúsculas), crea la tabla `logs` en SQLite `:memory:`, inserta con `executemany` y marcadores `?`, traduce la regla con `sqliteBackend(processing_pipeline=sysmon_pipeline())` y ejecuta la consulta. Resultado: 184 eventos, 1 alerta.
- Limitación conocida: el pipeline de Sysmon añade `EventID=1`, pero **no comprueba el canal** (`Channel`). Con más datasets podría generar coincidencias falsas con EventID 1 de otros registros. Pendiente de revisar.

### Fase 3 — Validador. HECHA
`validar.py <ruta>` en tres niveles:
1. **Leer y traducir** (ERROR si falla): intenta convertir la regla con el backend SQLite + pipeline Sysmon.
2. **Requisitos del proyecto** (ERROR si falla): debe tener al menos una técnica ATT&CK (`tag.namespace == "attack"` y `tag.name` empieza por `t`) y pasar el validador `attacktag` de pySigma. Decisión de Juan: un ATT&CK inventado descarta la regla, porque la tabla de resultados se organiza por técnica y es señal de alucinación.
3. **Buenas prácticas** (solo AVISO): resto de validadores de `sigma.validators.core`, excluyendo `attacktag` y `d3_fendtag` (este último necesita internet y no se usa).

Detalles: la traducción **modifica el objeto regla** (el pipeline lo anota), así que el nivel 2 y 3 se hacen sobre una copia recién cargada del texto. La función `descartar()` imprime el motivo y sale con `sys.exit(1)`.

### Fase 4 — Conectar la IA. EN CURSO (aquí lo dejamos)
- Elección: **Gemini, nivel gratuito**, vía `google-genai` (`genai.Client()` lee `GEMINI_API_KEY` del entorno tras `load_dotenv()`).
- Modelo fijado en `config.py` (sin alias `-latest`, por reproducibilidad).
- Problemas encontrados:
  - `gemini-2.5-flash` → `404`: no disponible para usuarios nuevos; el mensaje recomienda `gemini-3.8-flash` (y la "Interactions API").
  - `gemini-3.8-flash` → respondió una vez en 72,7 s con `thinking_level=LOW`; otras veces `504 DEADLINE_EXCEEDED` con timeout de 60 s y de 120 s. Diagnóstico: el servicio gratuito está saturado; no es un fallo del código, la clave ni la red (`listar_modelos.py` responde al instante).
  - `ThinkingLevel.MINIMAL` → `400`: no soportado por `gemini-3.8-flash`; su mínimo es `LOW`.
  - Por defecto el SDK no tiene timeout; hay que poner `types.HttpOptions(timeout=<ms>)`.
- `probar_modelos.py` (timeout 30 s, sin reintentos), resultado del 2026-10-21: `3.8-flash` → `504`; `3.7-flash` OK en 18 s; `3.6-flash` OK en 1-2 s (estable en 3 rondas); `3.5-flash` OK en 1-7 s; `3.5-flash-lite` OK en 7 s; `3.1-flash-lite` → `503`.
- **Modelo elegido: `gemini-3.6-flash`** (ya en `config.py`). Con la pregunta de `hola_ia.py` tarda unos 30 s, porque genera unos 336 tokens de razonamiento.
- **Límite del nivel gratuito: 5 peticiones por minuto y modelo** (`429 RESOURCE_EXHAUSTED`, `GenerateRequestsPerMinutePerProjectPerModel-FreeTier`). El error trae `retryDelay`. El bucle de corrección y las métricas (varias reglas por descripción) deben espaciar las llamadas o esperar y reintentar al recibir un `429`.
- Ollama queda como alternativa y para la comparativa entre modelos.
- **Hecho (2026-10-21)**:
  - `validar.py` → función `validar(texto)`, que devuelve `{motivo, detalles, avisos, tecnicas}` (`motivo` es `None` si la regla vale). `detector.py` → `cargar_eventos(ruta)` y `detectar(texto_regla, con)`. Ambos siguen funcionando desde la línea de comandos igual que antes.
  - `ia.py` → `preguntar(instrucciones, conversacion)`, con la conversación como pares `(rol, texto)`. Reintenta ante `429` (espera el `retryDelay`) y ante `503`/`504` (10, 20, 40 s). Devuelve el texto y los datos de la llamada: modelo, segundos y tokens. Es la capa intercambiable: para Ollama bastaría otro módulo con la misma función.
  - `generar.py ["descripción"]` → prompt de sistema (solo YAML, telemetría Sysmon, ATT&CK obligatorio), limpieza de bloques Markdown y **bucle de corrección** (`MAX_INTENTOS = 3`; devuelve la regla y el error en la misma conversación). Guarda la regla en `reglas/generadas/regla_<fecha>.yml` y la ejecuta con el detector.
  - Resultado: la regla generada para LSASS/comsvcs es válida al primer intento y da 1 alerta. El bucle se ha probado inyectando `attack.t9999` como primera respuesta: Gemini lo corrigió en el intento 2.
  - Detalle: el modelo pone `date: 2023/10/25` (formato antiguo) y `author: Detection Engineer`. Los validadores no lo avisan.

### Fase 5 — Métricas. EN CURSO (aquí lo dejamos, 2026-10-21)
- Conceptos ya explicados: verdadero positivo, falso negativo (ejemplo: cambiar `MiniDump` por `MiniDumpX` dio 0 alertas), falso positivo, verdadero negativo.
- **Hecho** (commit `4824eb7`):
  - `descargar.py` baja el dataset de LSASS y 5 controles negativos de otras tácticas: `psh_python_webserver` (execution), `cmd_seatbelt_group_user` (discovery), `cmd_mshta_vbscript_execute_psh` (defense_evasion), `schtask_create` (lateral_movement) y `empire_persistence_registry_modification_run_keys_standard_user` (persistence, 40 569 eventos, 80 MB).
  - `detector.py`: `crear_backend()` = pipeline Sysmon + etapa propia que añade `Channel='Microsoft-Windows-Sysmon/Operational'`. La limitación del canal era real: el dataset de Empire tiene 4 eventos EventID 1 del canal `System`. Además, salta líneas en blanco (las tiene `schtask_create`) y guarda listas y diccionarios como texto JSON (los tiene Empire). `validar.py` usa el mismo backend.
  - `metricas.py`: genera `REGLAS_POR_CASO = 5` reglas por caso (`CASOS`: técnica, descripción, dataset y regla de referencia). La **regla de referencia manual** marca qué eventos son el ataque real. Detección real = alertas que coinciden con ella; falso positivo = cualquier otra alerta, en el dataset del ataque o en los negativos. Si la API falla, lo anota y sigue. Guarda las reglas en `reglas/generadas/<técnica>/` y los resultados en `resultados/metricas_<modelo>_<fecha>.json`, e imprime una tabla Markdown.
- **Bloqueo: cuota diaria de Gemini gratis = 20 peticiones por día y modelo** (`GenerateRequestsPerDayPerProjectPerModel-FreeTier`). Se agotó para `3.6-flash` y `3.5-flash` el 2026-10-21, y la primera ejecución de `metricas.py` dio 0/5 (503 y 429). `ia.py` ya no espera ante un límite diario (`"PerDay"` en el error). Los 503 son frecuentes.
- Al cerrar la sesión quedó lanzada una prueba de `metricas.py` con `gemini-3.5-flash-lite` (forzado con `runpy`, sin tocar `config.py`). Su resultado no se llegó a ver. Si existe `resultados/`, revisarlo y decidir si se versiona.
- **Siguiente decisión (para Juan)**: 20 peticiones al día no bastan (5 reglas × hasta 3 intentos × varias técnicas). Opciones:
  1. **Ollama local** en la GPU (recomendado): sin cuotas; módulo nuevo con la misma `preguntar()`. Requiere instalar Ollama y elegir el modelo (por ejemplo, `qwen` o `llama` de 7-8B).
  2. Gemini de pago.
  3. Repartir las ejecuciones en varios días. Gemini se quedaría solo para la comparativa.
- **Decisión de Juan (2026-10-27): Ollama local.** La prueba con `gemini-3.5-flash-lite` no dejó resultados.
- **Hecho (2026-10-27)**:
  - `config.py`: `PROVEEDOR` ("gemini" u "ollama") y `MODELOS` por proveedor. `ia.py` solo elige el módulo; el código de Gemini está en `ia_gemini.py`; `ia_ollama.py` tiene la misma `preguntar()` (rol "model" pasa a "assistant", `num_ctx` 8192, sin reintentos). `metricas.py` cambia ":" por "-" en los nombres de archivo.
  - Medición con `qwen2.5-coder:7b` sin tocar el prompt (decisión de Juan: medir tal cual): **T1003.001 → 4/5 válidas, 0/5 detectan, 0 FP**, unos 7-12 s por respuesta. Resultados en `resultados/` (se versiona).
  - Fallos del modelo: usa `TargetFilename`/`TargetImage`, que **no existen en process_creation**, así que la regla nunca coincide; `id` que no es UUID; YAML inválido (`'a' or 'b'`); en el bucle de corrección repite la misma respuesta.
- Cambios en el validador (nivel 2, ERROR): los campos deben existir en el evento de Sysmon de la categoría (`campos_sysmon.py`, más `EventID` y `Channel`), y el `logsource` debe indicar `category`, porque sin ella el pipeline no filtra por EventID. En el nivel 1, mensajes claros para dos errores de pySigma que el modelo no entendía: regla en lista YAML (`- title:`) y `condition` escrita con campos en lugar de nombres de selección (`PISTA_CONDICION`).
- `config.py`: el modelo se puede cambiar con `$env:MODELO = "qwen3:8b"`. `ia_ollama.py` activa `think` si el modelo lo admite (`qwen3`). Ollama no separa los tokens de razonamiento.
- Mediciones T1003.001 (5 reglas, `resultados/`):

  | Modelo | Validador | Válidas | Detectan | Segundos por regla |
  |---|---|---|---|---|
  | qwen2.5-coder:7b | inicial | 4/5 | 0/5 | 12.6 |
  | qwen2.5-coder:7b | + campos | 4/5 | 1/5 | 22.8 |
  | qwen2.5-coder:7b | + pistas | 5/5 | 0/5 | 13.8 |
  | qwen3:8b | + campos | 0/5 | 0/5 | 207.7 |
  | qwen3:8b | + pistas | 1/5 | 0/5 | 202.9 |

- Conclusión: el bucle de corrección con mensajes claros sube la **validez**, pero los modelos de 7-8B fallan en la **lógica** (padre/hijo invertidos, `lsass.exe` como `ParentImage`, `comsvcs.dll,MiniDump` con coma). Eso solo lo detecta la prueba contra datos reales. `qwen3:8b` es unas 15 veces más lento y peor en sintaxis Sigma. Con 5 reglas la variación entre ejecuciones es grande (0/5 o 1/5).
### Fase 6 — Escalar y presentar. CASI HECHA (aquí lo dejamos, 2026-10-27 noche)
Juan pidió "haz todo lo que quede para subirlo a GitHub" y, al ver los resultados, decidió **dejar los modelos como están** (sin más mejoras de prompt). Hecho:
- **6 técnicas** en `metricas.py`, reutilizando los datasets ya descargados: cada dataset es el ataque de su caso y control negativo de los otros 5. Reglas de referencia a mano en `reglas/`: `lsass_comsvcs` (T1003.001), `mshta_vbscript` (T1218.005), `schtasks_create` (T1053.005), `run_key_powershell` (T1547.001, `registry_set`), `netsh_firewall_regla` (T1686.003) y `seatbelt` (T1082). Matriz comprobada: cada una salta solo en su dataset.
- **ATT&CK v20** en pySigma: Defense Evasion ya no existe (ahora `stealth` y `defense-impairment`), y T1562.004 pasó a T1686.003. El validador explica las tácticas válidas y la táctica de cada técnica.
- Validador: una categoría que no está en `sysmon_generic_logsource_eventid_mapping` (p. ej. `registry`) da ERROR. `detector.detectar()` devuelve `[]` si falta la columna (`no such column`); antes tiraba la medición. `metricas.py` anota los errores de ejecución y sigue.
- `generar.py`: regla de ejemplo (certutil, T1105) en el prompt; `CON_EJEMPLO=0` la quita. Variables de entorno: `PROVEEDOR`, `MODELO`, `CON_EJEMPLO`, `REGLAS_POR_CASO`.
- Criterio: una regla **detecta** si alerta en al menos un evento del ataque. `resumen.py` usa la última medición por (modelo, prompt), no cuenta los errores de la API y saca 3 tablas.
- `requirements.txt` (probado en un venv limpio), `LICENSE` (MIT), `README.md` (escrito, **sin commit**; tiene `<!-- RESULTADOS -->` para pegar la salida de `resumen.py`).
- Revisión de secretos: el historial no tiene la clave (solo el texto `GEMINI_API_KEY=...` de este archivo); `.env` y `datos/` nunca se han versionado.
- Resultados (detectan sin FP): gemini-3.6-flash con ejemplo 8/8 (4 peticiones fallaron por cuota/500; T1082 sin datos); qwen2.5-coder:7b 3/30 con y sin ejemplo (válidas 77 % y 60 %); qwen3:8b con ejemplo 1/18 (válidas 83 %). `gemini-3.5-flash` se quedó sin cuota tras 2 reglas y se borró.
- Hallazgo para el README: `qwen3` copia del ejemplo el bloque `filtro_legitimo` y excluye `ParentImage: cmd.exe`, justo el padre del ataque de Seatbelt. El ejemplo enseña el formato, pero también contagia lógica.

**Pendiente al retomar:**
1. Al cerrar quedó en marcha `qwen3:8b` **sin ejemplo** (3 reglas por caso). Si no existe `resultados\metricas_qwen3-8b_sin-ejemplo_*.json`, borrar `reglas\generadas\*\qwen3-8b_sin-ejemplo_*` y relanzar: `$env:PROVEEDOR='ollama'; $env:MODELO='qwen3:8b'; $env:CON_EJEMPLO='0'; $env:REGLAS_POR_CASO='3'; python metricas.py` (unos 40 min).
2. `python resumen.py` → pegar las tablas en el README (sección Resultados) con un comentario corto: Gemini detecta casi siempre y los locales casi nunca; validez ≠ detección; el efecto del ejemplo.
3. Commit del README.
4. Publicar (preguntar a Juan antes): `gh` no está instalado y no hay remoto. Opciones: crear el repositorio vacío `sigma-ai-validator` en github.com y hacer `git remote add origin ...` + `git push`, o instalar `gh` (`winget install GitHub.cli`, `gh auth login`). Proponer renombrar la rama `master` a `main`.
5. Avisar a Juan: los commits llevan el correo `al416013@uji.es`, que será público. Si no lo quiere, se puede usar el correo noreply de GitHub para los commits nuevos; cambiar los antiguos implica reescribir el historial, así que es decisión suya.
6. Decidir si CLAUDE.md se publica (contiene notas personales de trabajo) o se añade a `.gitignore` / se saca del índice.

## Convenciones

- Código y comentarios en español, salvo nombres de librerías.
- Los scripts se ejecutan desde la raíz del proyecto con el `.venv` activo: `python <script>.py`.
- Antes de cada `commit`, `git status` para comprobar que `.env` y `datos/` no aparecen.
