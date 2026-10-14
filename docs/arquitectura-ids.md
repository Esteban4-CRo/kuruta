# Arquitectura de Kuruta

## Decisión tecnológica

Kuruta utiliza una arquitectura híbrida:

- **Rust** para el sensor/agente de host. Produce un binario nativo para Windows
  y Linux, con bajo consumo y una base de código compartida. El código específico
  de cada sistema se puede aislar en módulos `cfg` cuando se agreguen fuentes
  nativas como Windows Event Log, ETW, journald o auditd.
- **Python y FastAPI** para la API, validación de eventos, motor inicial de reglas
  y persistencia SQLite. El ecosistema permite evolucionar rápidamente la
  ingestión y las reglas.
- **JSON** para el esquema de eventos y las reglas acotadas; las reglas comparan
  campos y no ejecutan código, expresiones ni comandos del sistema.

Python y Rust no son opciones excluyentes: Rust ejecuta el componente cercano al
sistema operativo y Python facilita cambiar la lógica del servicio. El coste es
mantener dos toolchains y un contrato común; `schemas/event-v1.json` y los
modelos Pydantic fijan ese contrato.

## Implementación actual y alcance

El MVP implementa observación de inicio de procesos local. El agente Rust sondea
procesos cada cinco segundos, informa solo los nuevos desde su arranque y envía
los eventos al backend por HTTP. El backend valida el evento, lo guarda en SQLite
y ejecuta reglas de coincidencia exacta para herramientas conocidas de
inspección de red. Una alerta es una señal revisable y no prueba una intrusión.
Al ser sondeo, puede perder procesos que comiencen y terminen entre dos lecturas.

**Todavía no hay captura de paquetes, observación de Windows Event Log/ETW,
journald, auditd, gestión de incidentes, frontend web, autenticación del agente,
TLS entre equipos ni instalación de servicios nativos.** El backend escucha en
`127.0.0.1` por defecto; no cambiar ese valor para exponerlo a la LAN sin
implementar primero autenticación por agente, TLS, autorización y pruebas.

Los paquetes descargables son ZIP x64 nativos que incluyen el servidor generado
por PyInstaller, agente Rust, reglas y scripts de inicio. La CI compila Windows
y Linux en runners nativos al publicar una etiqueta `v*`.

El agente no ve todos los dispositivos de la red doméstica. Para inspeccionar
tráfico de varios dispositivos se necesita que un sensor reciba los paquetes
desde un TAP, puerto espejo/SPAN de un switch administrable o un gateway con esa
función. El modo promiscuo de una tarjeta Wi-Fi común no da automáticamente
visibilidad del tráfico unicast de otros clientes.

## Flujo implementado

```text
Windows/Linux
  agente Rust -- nuevos procesos, sin argumentos de comando
       |
       | HTTP local: POST /api/v1/events
       v
  FastAPI -- tamaño máximo y validación Pydantic
       |
       +--> motor de reglas JSON -- coincidencia exacta
       |
       +--> SQLite -- evento y alertas en una transacción
       |
       +--> GET /api/v1/events y GET /api/v1/alerts
```

## Estructura y responsabilidad

| Ruta | Estado y responsabilidad |
| --- | --- |
| `agents/kuruta-agent/src/main.rs` | Implementado: sondeo de procesos, cola en memoria, reintento de envío HTTP y creación de eventos. |
| `agents/kuruta-agent/Cargo.toml` | Dependencias y configuración del binario Rust. |
| `scripts/build_release.py` | Construye el servidor con PyInstaller y ensambla el ZIP de cada SO. |
| `packaging/` | Scripts de inicio y parada y guía incluida en las descargas. |
| `.github/workflows/release.yml` | Compila y publica ZIP para Windows y Linux al crear etiquetas `v*`. |
| `LICENSE` | Licencia MIT del proyecto. |
| `agents/windows/README.md` | Alcance y compilación del agente en Windows; no instala servicios aún. |
| `agents/linux/README.md` | Alcance y compilación del agente en Linux; no instala servicios aún. |
| `backend/api/app.py` | Rutas HTTP, límite de cuerpo y ensamblaje de componentes. |
| `backend/ingestion/schema.py` | Modelos validados para eventos, alertas y salud. |
| `backend/ingestion/detection.py` | Carga de reglas JSON y comparación de campos. |
| `backend/ingestion/store.py` | Esquema SQLite, escritura idempotente y consultas recientes. |
| `rules/windows/` y `rules/linux/` | Reglas de alerta por sistema operativo. |
| `schemas/event-v1.json` | Contrato JSON del evento v1. |
| `tests/unit/test_ingestion.py` | Pruebas de esquema, reglas, almacenamiento y API. |
| `assets/kuruta-logo.png` | Logo proporcionado por el usuario, incluido en el proyecto. |
| `frontend/` e `infrastructure/` | Reservadas para una consola y despliegue futuros; sin implementación todavía. |

## Contrato de eventos v1

```json
{
  "schema_version": 1,
  "event_id": "uuid",
  "timestamp": "2026-10-14T12:00:00Z",
  "host": {
    "id": "linux:equipo-casa",
    "hostname": "equipo-casa",
    "platform": "linux"
  },
  "source": "host",
  "event_type": "process.started",
  "severity": "info",
  "data": {
    "pid": 1234,
    "name": "nmap"
  }
}
```

- `schema_version` fija la versión del contrato.
- `event_id` permite reintentar sin duplicar evento o alerta.
- `timestamp` es UTC en formato RFC 3339.
- `host.id`, `hostname` y `platform` identifican el origen y plataforma.
- `source`, `event_type` y `severity` describen el evento.
- `data` contiene valores escalares limitados. El agente no envía argumentos ni
  contenido de paquetes.

## Seguridad y privacidad actuales

- El servicio escucha en loopback por defecto y no autentica agentes. Esto es
  aceptable solo para la prueba local; no es un diseño seguro para una API
  expuesta a la red.
- Los eventos incluyen hostname, nombre de proceso y PID. La base `data/` se
  ignora en Git y debe protegerse con permisos del sistema operativo.
- La cola del agente solo vive en memoria, está limitada a 500 eventos y descarta
  el más antiguo al llenarse, informándolo por stderr.
- Los fallos de red se reportan en stderr y el agente conserva el evento en la
  cola para reintentar en el siguiente ciclo.
- El MVP no bloquea tráfico, no termina procesos ni ejecuta respuesta automática.
- Las herramientas detectadas también se usan legítimamente; se requiere revisión
  humana antes de tomar medidas.

## Próximas etapas recomendadas

1. Añadir autenticación individual y revocable por agente y HTTPS antes de aceptar
   eventos desde otros equipos de la LAN.
2. Añadir fuentes nativas por sistema: Windows Event Log/ETW y journald/auditd,
   minimizando privilegios y documentando sus permisos.
3. Añadir incidentes, retención configurable, exportación y una consola local.
4. Diseñar un sensor de red pasivo separado y probarlo en un puerto espejo o TAP;
   no prometer visibilidad que la topología de red no provea.
5. Automatizar compilaciones y pruebas en Windows y Linux, además de distribución,
   actualización segura, firma y desinstalación.
