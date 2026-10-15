# Agente Kuruta en Linux

El sensor de procesos compartido está en `agents/kuruta-agent/`. La captura de
paquetes no vive en este binario: forma parte de `kuruta-linux-x64` (Scapy +
libpcap).

```bash
cargo build --release --manifest-path agents/kuruta-agent/Cargo.toml
```

El agente solo consulta procesos visibles para la cuenta que lo ejecuta. Para
el sniffer, otorga `cap_net_raw` y `cap_net_admin` al ejecutable de la app o
arráncalo con privilegios de captura.
