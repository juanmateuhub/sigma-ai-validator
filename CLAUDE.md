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
- Hardware: tarjeta gráfica NVIDIA con 8 GB o más de VRAM (útil para modelos locales con Ollama).

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
└── probar_modelos.py         # prueba varios modelos Gemini de golpe (resultado pendiente)
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

### Fase 5 — Métricas. PENDIENTE
- Conceptos ya explicados: verdadero positivo, falso negativo (ejemplo: cambiar `MiniDump` por `MiniDumpX` dio 0 alertas), falso positivo, verdadero negativo.
- Las IAs no son deterministas: generar **varias reglas por descripción** y medir cuántas pasan la validación y detectan el ataque ("4 de 5").
- Falsos positivos: decidir con Juan qué usar como actividad "normal". Propuesta: ejecutar cada regla contra datasets de **otras técnicas** como control negativo, y valorar si hay datos benignos adecuados.
- Registrar tiempo de respuesta y tokens (`response.usage_metadata`) por regla.

### Fase 6 — Escalar y presentar. PENDIENTE
- Varias técnicas ATT&CK con sus datasets de OTRF.
- Tabla de resultados por técnica (y por modelo si se hace la comparativa).
- README atractivo para reclutadores, `requirements.txt`, y subir el repositorio a GitHub.

## Convenciones

- Código y comentarios en español, salvo nombres de librerías.
- Los scripts se ejecutan desde la raíz del proyecto con el `.venv` activo: `python <script>.py`.
- Antes de cada `commit`, `git status` para comprobar que `.env` y `datos/` no aparecen.
