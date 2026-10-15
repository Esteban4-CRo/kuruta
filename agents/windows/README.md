# Agente Kuruta en Windows

El sensor de procesos compartido está en `agents/kuruta-agent/`. La captura de
paquetes no vive en este binario: forma parte de la aplicación de escritorio
`kuruta-windows-x64.exe` (Scapy + Npcap).

```powershell
cargo build --release --manifest-path agents/kuruta-agent/Cargo.toml
```

El agente solo consulta procesos visibles para la cuenta que lo ejecuta. No
instala un servicio, no eleva privilegios y no obtiene argumentos de línea de
comandos. Para el sniffer, instala Npcap y ejecuta la app Kuruta; usa
administrador si la NIC lo exige.
