# Kuruta IDS

<table>
  <tr>
    <td width="170" align="center">
      <img src="assets/kuruta-logo.png" width="145" alt="Logo oficial de Kuruta">
    </td>
    <td>
      <strong>IDS local, sniffer y consola de escritorio.</strong><br>
      Kuruta captura el tráfico de la interfaz que elijas, lo disecciona al estilo
      de un analizador de paquetes, señala anomalías de red y sigue observando
      procesos del host con el agente Rust.
    </td>
  </tr>
</table>

> Kuruta es pasivo y local. No sustituye a un antivirus, firewall o NIDS
> profesional. Las anomalías son señales para revisar, no una prueba de
> intrusión. El sniffer ve el tráfico que llega a la interfaz de captura; una
> tarjeta Wi-Fi en modo promiscuo no muestra automáticamente el unicast de
> otros clientes.

## Pilares Fundamentales de Kuruta

1. **Sniffer de Red de Alto Rendimiento**: Captura con Scapy/Npcap y fallback de sockets raw, inspección profunda L2/L3/L4/L7 al estilo Wireshark, seguimiento de streams TCP/UDP, filtros de visualización avanzados, jerarquía de protocolos y exportación/importación estándar PCAP.
2. **IDS Heurístico (Intrusion Detection System)**: Detección analítica de escaneos de puertos (vertical y horizontal), inundaciones SYN/ICMP, exfiltración por túneles DNS mediante entropía de Shannon, combinaciones de flags prohibidas (RFC 793) y envenenamiento ARP.
3. **IPS Reactivo (Intrusion Prevention System)**: Defensa perimetral activa. Aislamiento automático de hosts agresores en memoria y en las reglas del Firewall del sistema operativo (WFP / netsh / iptables), inyección de tramas de terminación TCP RST, búfer de cuarentena y auditoría de mitigaciones.
4. **NAC Zero-Trust (Network Access Control)**: Descubrimiento y perfilado continuo de activos, identificación de fabricante por base OUI (Apple, Cisco, Espressif, Raspberry Pi, etc.), detección de sistema operativo por TTL, detección de Rogue Gateways (ARP Hijack) y servidores DHCP no autorizados.

## Descarga e Instalación (Windows y Linux)

En GitHub abre **[Releases](https://github.com/Esteban4-CRo/kuruta/releases)** y descarga el paquete correspondiente a tu sistema. Al igual que aplicaciones como Obsidian o Wireshark, dispones de instaladores completos con icono oficial, accesos directos y versiones portables:

### Windows x64
- **Instalador recomendado**: `Kuruta-Setup-windows-x64.exe` (Doble clic, asistente de instalación, crea accesos directos en Escritorio y Menú Inicio con el icono oficial y desinstalador).
- **Portable**: `kuruta-windows-x64.exe` (Ejecutable directo sin instalación).
- **Requisito para capturar tráfico**: Instala [Npcap](https://npcap.com/#download) (el mismo motor que utiliza Wireshark).

### Linux x64
- **Paquete Debian / Ubuntu / Kali / Mint**: `kuruta-linux-x64.deb`
  ```bash
  sudo dpkg -i kuruta-linux-x64.deb
  ```
  *Configura automáticamente permisos `setcap` e integra el icono y lanzador en el menú de aplicaciones del sistema.*
- **Paquete Universal (Arch, Fedora, openSUSE)**: `kuruta-linux-x64.tar.gz`
  ```bash
  tar -xzvf kuruta-linux-x64.tar.gz
  cd kuruta-linux-x64
  sudo ./install.sh
  ```
- **Binario portable directo**: `kuruta-linux-x64`
  ```bash
  chmod +x kuruta-linux-x64
  sudo setcap cap_net_raw,cap_net_admin=eip ./kuruta-linux-x64
  ./kuruta-linux-x64
  ```

Datos locales: `%LOCALAPPDATA%\Kuruta\` en Windows y `~/.local/share/kuruta/` en Linux.

GitHub Actions compila automáticamente todos los instaladores al publicar una etiqueta `v*` o mediante ejecución manual de workflow.

## Uso de la consola

- **Paquetes**: tabla No. / Tiempo / Origen / Destino / Proto / Len / Info.
  Un clic abre el árbol y el hex; doble clic sigue el stream.
- **Filtro de visualización**: `tcp`, `dns`, `http or tls`,
  `ip.addr == 192.168.1.10`, `tcp.port == 443`, `frame contains GET`.
- **Anomalías** y **Alertas**: hallazgos de la captura y coincidencias de reglas.
- **Host**: eventos del agente de procesos, si lo tienes en marcha.
- **PCAP**: descarga el buffer actual para abrirlo en Wireshark.

## Desarrollo desde el código

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m backend
```

Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m backend
```

La consola queda en `http://127.0.0.1:8765/`. `--headless` arranca solo el
servicio. `KURUTA_DB_PATH` y `KURUTA_RULES_DIR` siguen disponibles.

Agente de procesos, en otra terminal:

```text
cargo run --manifest-path agents/kuruta-agent/Cargo.toml
```

## API local

- `GET /` consola gráfica
- `GET /health`
- `GET|POST /api/v1/events`, `GET /api/v1/alerts`
- `GET /api/v1/sniffer/interfaces|status|packets|stats|anomalies`
- `POST /api/v1/sniffer/start|stop|clear`
- `GET /api/v1/sniffer/export.pcap`
- `WS /api/v1/sniffer/live`

El `POST /api/v1/events` sigue limitado a 64 KiB. El servidor enlazado a
loopback no está pensado para agentes remotas sin autenticación y TLS.

## Pruebas

```text
python -m pytest
cargo test --manifest-path agents/kuruta-agent/Cargo.toml
```

## Licencia

Kuruta se distribuye bajo la licencia [MIT](LICENSE).
