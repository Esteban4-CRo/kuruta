# Agente Kuruta en Linux

El agente compartido está en `agents/kuruta-agent/`; esta carpeta describe el
despliegue específico de Linux. El MVP compila para Linux x86_64 con una
instalación estable de Rust y Cargo:

```bash
cargo build --release --manifest-path agents/kuruta-agent/Cargo.toml
```

El ejecutable se genera bajo `agents/kuruta-agent/target/release/kuruta-agent`.

El agente solo consulta procesos visibles para la cuenta que lo ejecuta. No
instala una unidad `systemd`, no eleva privilegios, no obtiene argumentos de
línea de comandos y no captura paquetes. Las fuentes de `auditd`, journald,
eBPF y captura libpcap no están implementadas todavía.
