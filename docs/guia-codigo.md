# Guía del código de Kuruta

Esta guía explica el código del MVP por líneas y bloques consecutivos. Los
números corresponden a la versión inicial de este repositorio; al editar un
archivo, deben actualizarse los números de referencia. Las líneas en blanco solo
separan bloques y no ejecutan lógica.

## Servicio HTTP — `backend/api/app.py`

| Líneas | Explicación |
| --- | --- |
| 1 | Docstring del módulo: identifica la API como recolector HTTP local. |
| 3 | Activa anotaciones diferidas para los tipos. |
| 5–12 | Importa logging, entorno, rutas, tipos, FastAPI y primitivas ASGI para leer el cuerpo HTTP con límite real. |
| 14–16 | Importa el motor de reglas, modelos de API y almacén SQLite. |
| 18–20 | Define el logger, la raíz del proyecto y el máximo de 64 KiB por evento. |
| 23–28 | Declara el middleware y guarda la aplicación ASGI y el límite que usará. |
| 30–38 | Detecta únicamente `POST /api/v1/events`; para las demás rutas delega la petición sin alterar su cuerpo. |
| 40–48 | Acumula fragmentos del cuerpo en memoria y cuenta bytes, también cuando el cliente transmite el cuerpo por partes. |
| 49–64 | Si supera el máximo, devuelve HTTP 413 en formato JSON y no pasa el evento al parser ni al backend. |
| 65–78 | Guarda cada fragmento válido, crea un receptor que los reproduce para FastAPI y delega la solicitud. |
| 83–87 | Firma y docstring de la fábrica; permite inyectar rutas de base de datos y reglas en pruebas. |
| 88–95 | Selecciona rutas desde parámetros, variables de entorno o valores locales; crea los objetos de almacenamiento y reglas. |
| 97–101 | Define el ciclo de vida ASGI: inicializa las tablas antes de aceptar peticiones. |
| 103–108 | Crea FastAPI con título, versión, descripción y ciclo de vida. |
| 109–110 | Expone el almacén y el motor a las rutas mediante `app.state`. |
| 111–114 | Registra el middleware que impone el límite al endpoint de ingestión. |
| 116–119 | Define `GET /health`, que devuelve únicamente el estado y nombre del servicio. |
| 121–134 | Define `POST /api/v1/events`: evalúa reglas, persiste evento y alertas; informa duplicados de forma idempotente. |
| 136–142 | Define `GET /api/v1/events` y limita la consulta a entre 1 y 500 resultados. |
| 144–150 | Define `GET /api/v1/alerts`, con el mismo límite de paginación sencillo. |
| 152–155 | Devuelve la instancia creada y construye la aplicación ASGI importable por Uvicorn. |

Las funciones `default_data_directory` y `bundled_rules_directory`, dentro del
bloque inicial de `backend/api/app.py`, eligen la ruta de datos por usuario y
encuentran las reglas incluidas en el ejecutable PyInstaller. Consulta el código
actual antes de usar números de línea, ya que el archivo evoluciona.

## Contrato de datos — `backend/ingestion/schema.py`

| Líneas | Explicación |
| --- | --- |
| 1–8 | Describe el módulo, activa anotaciones diferidas e importa tipos de Python y validadores Pydantic. |
| 10 | Restringe la plataforma a `windows` o `linux`. |
| 11 | Enumera los cinco niveles de severidad aceptados. |
| 12 | Permite que los valores de datos sean escalares JSON, no objetos arbitrarios. |
| 15–22 | `HostIdentity` define identificador, hostname y plataforma, rechaza campos extra y limita longitudes. |
| 25–37 | `EventRecord` es el sobre común: versión 1, ID, hora, host, origen, tipo, severidad y hasta 32 campos de datos. Rechaza propiedades no declaradas. |
| 39–45 | Exige timestamp con zona horaria y lo normaliza a UTC. |
| 48–57 | `AlertRecord` describe una alerta guardada y su vínculo a evento/regla. |
| 60–64 | `HealthRecord` limita la respuesta de salud a estado `ok` y nombre de servicio. |
| 67–73 | `AlertDraft` modela la coincidencia de una regla antes de guardarla junto con el evento. |

## Motor de reglas — `backend/ingestion/detection.py`

| Líneas | Explicación |
| --- | --- |
| 1–11 | Importa JSON, rutas, validación y modelos compartidos; estos imports no ejecutan las reglas. |
| 14–26 | `DetectionRule` valida campos permitidos, identificador, nombre, descripción, severidad, tipo, plataformas, campo y lista de valores exactos. |
| 29–33 | `RuleEngine` conserva una lista inmutable por convención de reglas ya validadas. |
| 35–40 | Busca archivos JSON un nivel debajo de la carpeta de reglas; falla explícitamente si no hay ninguno. |
| 42–45 | Prepara el inventario de reglas e interpreta cada archivo como JSON UTF-8. |
| 46–49 | Valida cada objeto con Pydantic; convierte una regla inválida en un error que nombra el archivo. |
| 50–54 | Impide identificadores duplicados y devuelve el motor cargado. |
| 56–58 | Define evaluación y una lista vacía para las alertas coincidentes. |
| 59–64 | Descarta reglas con tipo, plataforma o valor del campo diferentes; la comparación es exacta. |
| 66–73 | Construye un borrador de alerta con el texto y severidad de la regla que coincidió. |
| 74 | Devuelve todas las alertas encontradas; una coincidencia no realiza acciones sobre el host. |

## Persistencia — `backend/ingestion/store.py`

| Líneas | Explicación |
| --- | --- |
| 1–11 | Describe el módulo e importa SQLite, JSON, cierre de conexiones, hora UTC, rutas y modelos. |
| 14–18 | `EventStore` conserva la ruta de base de datos recibida. |
| 20–24 | Abre una conexión con espera acotada, usa filas con nombres de columna y habilita claves foráneas. |
| 26–29 | Crea el directorio de datos y abre la transacción de inicialización; `closing` garantiza cierre. |
| 30–55 | Crea idempotentemente las tablas e índices de eventos y alertas; el ID de evento es clave primaria y la alerta referencia un evento. |
| 57–60 | Declara ingestión atómica, toma la hora de recepción UTC y abre conexión/transacción. |
| 61–75 | Inserta el sobre JSON usando parámetros SQL; `INSERT OR IGNORE` protege frente a reenvíos del mismo `event_id`. |
| 76–77 | Señala que el evento ya existía y evita volver a crear alertas. |
| 79–95 | Inserta cada alerta en la misma transacción; `event_id:rule_id` y la restricción única evitan duplicados. |
| 96 | Indica que un evento nuevo quedó guardado con éxito. |
| 98–105 | Consulta payloads recientes por hora y los vuelve a validar como `EventRecord`. |
| 107–118 | Consulta alertas recientes, también con un límite parametrizado y sin interpolar SQL. |
| 119–130 | Convierte cada fila SQL en un `AlertRecord` tipado que FastAPI puede serializar. |

## Agente multiplataforma — `agents/kuruta-agent/src/main.rs`

| Líneas | Explicación |
| --- | --- |
| 1 | Docstring del crate: el agente observa nuevos procesos en Windows y Linux. |
| 3–14 | Importa conjunto de PID, cola FIFO, variables de entorno, temporizador, cliente HTTP, serialización, procesos, URL y UUID. |
| 16–17 | Limita la cola de reintentos a 500 eventos y fija un sondeo de cinco segundos. |
| 19–20 | Rechaza en compilación sistemas distintos de Windows/Linux. |
| 22–25 | Selecciona la etiqueta de plataforma mediante compilación condicional. |
| 28–32 | Estructura del identificador de host que se serializará como JSON. |
| 35–44 | Estructura del sobre de evento v1 que coincide con el contrato del backend. |
| 46–48 | Obtiene hostname o devuelve un error explícito; no inventa un identificador si falla el sistema. |
| 50–61 | Lee el intervalo en segundos, usa 5 si no se definió y rechaza texto inválido o cero. |
| 62–87 | Lee y analiza la URL del backend; solo permite HTTP sin credenciales en `localhost` o una dirección IP loopback, para evitar enviar telemetría a otra máquina sin autenticación/TLS. |
| 89–91 | Copia los PID actualmente visibles a un conjunto para poder comparar ciclos. |
| 93–112 | Crea evento de inicio con UUID, hora RFC 3339, identidad del host y solo PID/nombre del proceso; no recopila argumentos. |
| 113–133 | Envía desde la cabeza de la cola; elimina tras éxito HTTP, conserva ante error y lo informa por stderr. |
| 135–142 | Lee configuración, construye cliente con timeout de tres segundos e inicializa el inventario y la cola. |
| 144 | Anuncia el arranque sin imprimir URL ni datos de entorno. |
| 146–150 | Espera, actualiza procesos y retira PID que ya no están presentes para reconocer su reutilización futura. |
| 152–162 | Detecta PID nuevos, crea eventos, limita la cola y advierte si debe descartar el elemento más antiguo. |
| 164–166 | Intenta entregar eventos pendientes en cada ciclo. |
| 168–173 | Punto de entrada del ejecutable: llama a `run`, informa fallos y termina con código distinto de cero si hay error. |

## Configuración y datos

- `pyproject.toml`: líneas 1–4 declaran el constructor del paquete; 6–13 fijan
  nombre, versión, requisitos de Python y dependencias del servicio; 15–18
  agrupan herramientas de prueba; el resto configura descubrimiento del backend
  y pytest.
- `agents/kuruta-agent/Cargo.toml`: declara el paquete Rust y sus bibliotecas,
  incluyendo `url` para analizar y restringir destinos a loopback.
- `backend/run_server.py`: arranca Uvicorn en `127.0.0.1:8765` tanto desde Python
  como desde el ejecutable empaquetado.
- `scripts/build_release.py`: ejecuta PyInstaller, compila Rust en el runner
  nativo y crea el ZIP con binarios, logo, licencia y guía de inicio.
- `packaging/start-kuruta.ps1` y `packaging/stop-kuruta.ps1`: inician y detienen
  backend y agente en Windows; guardan la base/logs bajo `%LOCALAPPDATA%\Kuruta`.
- `packaging/start-kuruta.sh`: inicia ambos procesos en Linux y los limpia al
  recibir Ctrl+C; los datos se guardan bajo `$XDG_DATA_HOME/kuruta` o
  `~/.local/share/kuruta`.
- `.github/workflows/release.yml`: ante una etiqueta `v*`, compila paquetes
  nativos Windows/Linux y los publica en GitHub Releases.
  `chrono` genera timestamps, `reqwest` entrega HTTP con TLS Rustls disponible,
  `serde`/`serde_json` producen el evento y `sysinfo` enumera procesos.
- `schemas/event-v1.json`: declara las mismas propiedades del sobre y evita
  campos desconocidos; el modelo Pydantic es la validación que usa realmente la
  API durante el MVP.
- `rules/windows/suspicious-tools.json` y `rules/linux/suspicious-tools.json`:
  cada archivo describe una coincidencia de proceso por nombre. Las herramientas
  listadas también pueden ser legítimas; la alerta media pide revisar el uso,
  no acusa automáticamente de una intrusión.
- `tests/unit/test_ingestion.py`: las pruebas fabrican eventos, prueban rechazo
  de campos inesperados, aislamiento de plataforma en las reglas, idempotencia
  del almacén, ingestión HTTP y límite de tamaño.
- `assets/kuruta-logo.png`: recurso gráfico proporcionado para la identidad del
  proyecto; no interviene en la recolección ni en la detección.
