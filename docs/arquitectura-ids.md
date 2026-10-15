# Arquitectura de Kuruta

## Decisión tecnológica

Kuruta utiliza una arquitectura híbrida:

- **Python / FastAPI / Scapy** para la aplicación de escritorio: captura local,
  disección de tramas, filtros, anomalías de red, API y consola HTML en blanco
  y negro. PyInstaller genera el ejecutable que el usuario descarga.
- **Rust** para el sensor opcional de host (inicios de proceso) en Windows y
  Linux, con el mismo contrato JSON.
- **JSON** para el esquema de eventos y las reglas acotadas; las reglas comparan
  campos y no ejecutan código.

La consola se sirve en `127.0.0.1:8765` y se abre en una ventana nativa
(WebView) o, si no hay runtime de ventana, en el navegador local.

## Flujo

```text
Interfaz de red (Npcap / libpcap)
       |
       v
  CaptureEngine (hilo Scapy) --> buffer circular
       |                         | lista, hex, PCAP, streams
       +--> AnomalyDetector -----+--> EventStore / reglas JSON
       |
       +--> WebSocket --> consola Kuruta (blanco y negro + logo)

Agente Rust (opcional)
       |
       | HTTP POST /api/v1/events
       v
  mismas reglas y SQLite
```

La captura observa el tráfico que la NIC entrega al proceso. Un puerto
espejo/SPAN, TAP o gateway sigue siendo necesario para ver otros hosts. El modo
promiscuo de una Wi-Fi doméstica no equivale a visibilidad de toda la LAN.

## Módulos

| Ruta | Responsabilidad |
| --- | --- |
| `frontend/` | Consola gráfica (paquetes, estadísticas, anomalías, alertas, host). |
| `backend/sniffer/capture.py` | Interfaces, hilo de captura, buffer, exporto PCAP. |
| `backend/sniffer/decode.py` | Filas, árbol de capas, info y hex. |
| `backend/sniffer/display_filter.py` | Filtro de visualización reducido. |
| `backend/sniffer/anomalies.py` | Señales estadísticas (scans, floods, ARP, DNS, volumen). |
| `backend/api/app.py` | API, WebSocket y ficheros estáticos. |
| `backend/run_app.py` | Arranque como aplicación de escritorio. |
| `agents/kuruta-agent/` | Sensor de procesos. |
| `rules/network/` | Reglas declarativas sobre eventos de red. |
| `scripts/build_release.py` | Binario de la app + agente por plataforma. |

## Límites

- Kuruta no bloquea tráfico ni mata procesos.
- El buffer de paquetes vive en memoria (unos 12 000 frames) y no es un almacén
  forense permanente; exporta PCAP si necesitas conservarlos.
- Las anomalías se retrasan con debounce para no inundar la consola.
- El backend permanece en loopback y no autentica clientes.

## Contrato de eventos v1

El sobre no cambia. Los hallazgos de red usan `source: "network"` y tipos como
`network.port_scan`, `network.syn_flood`, `network.arp_conflict`,
`network.tcp_scan_flags`, `network.icmp_flood`, `network.dns_anomaly` y
`network.volume_spike`. El campo `data.kind` es el que coinciden las reglas JSON.
