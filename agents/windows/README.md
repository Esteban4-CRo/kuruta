# Agente Kuruta en Windows

El agente compartido está en `agents/kuruta-agent/`; esta carpeta describe el
despliegue específico de Windows. El MVP compila para Windows x86_64 con una
instalación estable de Rust y Cargo:

```powershell
cargo build --release --manifest-path agents/kuruta-agent/Cargo.toml
```

El ejecutable queda en
`agents/kuruta-agent/target/release/kuruta-agent.exe` (Cargo puede ubicar el
directorio `target` relativo a la raíz del workspace Cargo).

El agente solo consulta procesos visibles para la cuenta que lo ejecuta. No
instala un servicio, no eleva privilegios, no obtiene argumentos de línea de
comandos y no captura paquetes. Ejecutarlo como servicio y endurecer el acceso
requiere configuración explícita de Windows y queda fuera del MVP.
