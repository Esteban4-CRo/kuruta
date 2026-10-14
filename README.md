# Kuruta IDS

![Kuruta logo](assets/kuruta-logo.png)


> **Estado: MVP en desarrollo.** Esta primera versión observa inicios de procesos en el equipo donde se ejecuta el agente. No inspecciona automáticamente todo el tráfico de la red doméstica ni sustituye a un antivirus, firewall o solución profesional de monitorización.

## Descripción del proyecto

Kuruta busca ofrecer visibilidad defensiva, sencilla y local sobre equipos de una red doméstica. El agente registra nuevos procesos sin recopilar argumentos de línea de comandos; el backend valida y guarda eventos en SQLite, aplica reglas declarativas y permite consultar alertas. Python facilita desarrollar la API y las reglas; Rust produce un agente nativo con una base compartida para Windows y Linux.

## Funciones del MVP

- Agente Rust para Windows y Linux que detecta nuevos procesos.
- Envío HTTP al backend local con una cola en memoria acotada mientras no haya conexión.
- API Python/FastAPI con validación de esquema y límite de tamaño de solicitud.
- Almacenamiento local en SQLite; no se suben eventos a un servicio de terceros.
- Reglas JSON por plataforma para señalar herramientas de escaneo y captura de paquetes.
- API para consultar la salud, eventos y alertas.
- Logo del proyecto incluido en `assets/kuruta-logo.png`.

## Arquitectura

```text
Windows/Linux
  Agente Rust (nuevos procesos)
       | HTTP a loopback
       v
  API FastAPI -> Validación -> Reglas JSON -> SQLite
       |                                  |
       +--------- eventos y alertas <-----+
```

Para recibir eventos de otro equipo hay que desplegar el backend en una dirección accesible desde la LAN y configurar el agente. **No expongas el servidor directamente a Internet.** Antes de aceptar conexiones de la LAN se debe añadir autenticación por agente y HTTPS; el servidor de este MVP escucha solo en `127.0.0.1` de forma predeterminada.

El agente observa procesos del equipo donde corre. La captura de paquetes requiere un sensor separado y visibilidad real del tráfico (por ejemplo, un puerto espejo/SPAN de un switch administrable, un TAP o un gateway configurado para ello). El modo promiscuo de una tarjeta Wi-Fi normal no muestra automáticamente las comunicaciones unicast de otros dispositivos.

## Requisitos

- Python 3.10 o posterior en el equipo del backend.
- Rust estable y Cargo para compilar el agente.
- Windows 10/11 o una distribución Linux con soporte de la versión de Rust instalada.

## Descargas para Windows y Linux

En GitHub abre **Releases** y descarga el paquete de tu sistema:

- Windows x64: `kuruta-windows-x64.zip`
- Linux x64: `kuruta-linux-x64.zip`

Extrae el ZIP completo y sigue `README-FIRST.txt` incluido. En Windows ejecuta
`start-kuruta.ps1` desde PowerShell; en Linux ejecuta `./start-kuruta.sh` desde
una terminal. Después abre `http://127.0.0.1:8765/docs`. No necesitas instalar
Python o Rust para ejecutar los ZIP.

GitHub Actions construye los paquetes nativos cuando se publica una etiqueta
`v*`. Windows no ejecuta el binario Linux ni Linux ejecuta el binario Windows.
Los paquetes están dirigidos a x64; para compilar localmente necesitas Python,
Rust y las dependencias de los manifiestos del proyecto.

## Puesta en marcha en Windows y Linux

Desde la raíz del repositorio:

### 1. Preparar el servicio

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m uvicorn backend.api.app:app --host 127.0.0.1 --port 8765
```

Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m uvicorn backend.api.app:app --host 127.0.0.1 --port 8765
```

La base de datos se crea en `data/kuruta.db`. Para cambiarla, define
`KURUTA_DB_PATH` con una ruta absoluta antes de iniciar el servidor. Para cambiar
el directorio de reglas, define `KURUTA_RULES_DIR`.

### 2. Compilar e iniciar el agente

En otra terminal, desde la raíz:

```text
cargo run --manifest-path agents/kuruta-agent/Cargo.toml
```

Por defecto, el agente envía eventos a
`http://127.0.0.1:8765/api/v1/events`. Ajusta `KURUTA_BACKEND_URL` para indicar
otra URL. `KURUTA_INTERVAL_SECONDS` controla el intervalo de sondeo (predeterminado
5 segundos). Solo se notifican procesos iniciados después del arranque del
agente, para evitar producir una alerta histórica masiva.

El agente no instala servicios del sistema ni requiere privilegios elevados
para enumerar procesos. Para que se inicie automáticamente, configura un servicio
de Windows o una unidad `systemd` siguiendo las instrucciones de tu sistema; la
instalación automática como servicio todavía no forma parte del MVP.

## API local

- `GET /health`: estado del servicio.
- `GET /api/v1/events?limit=100`: eventos recientes (límite de 1 a 500).
- `GET /api/v1/alerts?limit=100`: alertas recientes (límite de 1 a 500).
- `POST /api/v1/events`: ingesta de un evento que cumple el esquema versionado.
- `GET /docs`: documentación interactiva de la API mientras se ejecuta el servicio.

El endpoint POST acepta eventos de hasta 64 KiB y limita cada evento a 32 campos
simples. Los identificadores repetidos son idempotentes y no duplican alertas.
El servidor enlazado a loopback no está diseñado para aceptar agentes de otros
equipos sin controles adicionales.

## Reglas

Las reglas JSON están en `rules/windows/` y `rules/linux/`. Una coincidencia
compara el tipo de evento, la plataforma y un campo exacto del evento. El MVP
genera alertas de severidad media para herramientas de análisis de red conocidas.
Son herramientas legítimas en tareas administrativas: una coincidencia es una
señal para revisar, no una prueba de intrusión.

## Pruebas

```text
python -m pytest
```

Las pruebas cubren validación de eventos, ingestión/idempotencia, reglas y API.
El agente se puede comprobar con:

```text
cargo test --manifest-path agents/kuruta-agent/Cargo.toml
```

## Estructura

```text
agents/kuruta-agent/    Agente Rust compartido por Windows y Linux
agents/windows/        Notas y requisitos de despliegue para Windows
agents/linux/           Notas y requisitos de despliegue para Linux
backend/api/             API HTTP FastAPI
backend/ingestion/       Esquema, almacenamiento y motor de reglas
rules/windows/           Reglas específicas de Windows
rules/linux/             Reglas específicas de Linux
schemas/                 Contratos de eventos versionados
tests/unit/              Pruebas de backend y reglas
docs/                    Arquitectura y explicación de módulos
assets/                  Recursos oficiales de Kuruta
```

## Seguridad, privacidad y límites

- Kuruta es pasivo: no bloquea conexiones, mata procesos ni ejecuta acciones de
  respuesta automática.
- El agente no envía argumentos de procesos ni contenido de paquetes.
- Los eventos identifican el nombre del equipo y el nombre del proceso; la base
  local puede contener información del dispositivo y debe protegerse.
- Mantén el backend en loopback. No publiques el puerto en la LAN o Internet sin
  implementar y probar autenticación, TLS, autorización, rotación de credenciales
  y límites operativos.
- El usuario debe revisar las alertas: los nombres de herramientas conocidas
  pueden producir falsos positivos.
- La cola del agente es solo de memoria y tiene un máximo de 500 eventos; los
  eventos pendientes se pierden si el agente se cierra o se apaga el equipo.

## Documentación

- [Arquitectura y límites](docs/arquitectura-ids.md)
- [Guía explicativa del código](docs/guia-codigo.md)
- [Despliegue Windows](agents/windows/README.md)
- [Despliegue Linux](agents/linux/README.md)

## Licencia

Kuruta se distribuye bajo la licencia [MIT](LICENSE). Para crear una versión
descargable, publica una etiqueta, por ejemplo `v0.1.0`; GitHub Actions creará
los ZIP de Windows y Linux y los adjuntará al GitHub Release.
