# Lantern Network Scanner

Aplicación de escritorio para descubrir dispositivos y servicios TCP en una red local. Está construida completamente en Rust con `eframe/egui`, sin backend remoto ni frontend separado.

## Requisitos

- Rust estable instalado con [rustup](https://rustup.rs/)
- En Windows, las herramientas de compilación de C++ de Visual Studio o `rustup` con el toolchain MSVC

## Ejecutar

```powershell
cargo run --release
```

Escribe uno de estos destinos y pulsa **Start scan**:

- IP individual: `192.168.1.25`
- Rango inclusivo: `192.168.1.10-192.168.1.50`
- Red CIDR: `192.168.1.0/24`

El escaneo prueba los puertos TCP 22, 80, 443, 445 y 3389 con un timeout corto. Todo se ejecuta localmente.

Para soporte remoto con bloqueo consentido de entrada, consulta [GPO-DEPLOYMENT.md](GPO-DEPLOYMENT.md). Después de desplegar el agente por GPO y seleccionar una sesión, Lantern muestra `Request input lock` y `Unlock input`.

## Compilar ejecutable

```powershell
cargo build --release
```

El binario quedará en `target/release/lantern_scan.exe`.
