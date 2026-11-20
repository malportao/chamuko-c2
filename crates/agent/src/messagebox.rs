//! Cuadro de mensaje multiplataforma.
//!
//! Igual que el plugin de screenshot, la decision de *como* mostrar el dialogo
//! se separa de la ejecucion: `plan_messagebox` devuelve un plan (programa +
//! argumentos) y solo al ejecutar se lanza algo. Asi los tests cubren la
//! seleccion de backend y el escapado sin necesitar un servidor grafico.
//!
//! El texto lo escribe el operador, asi que llega a un script de PowerShell o
//! de AppleScript. Todo lo que entra en esos scripts se escapa aqui: un
//! mensaje como `'; rm -rf /; '` tiene que quedarse en texto y no ejecutarse.

use std::time::Duration;

use chamuko_plugin_api::{
    Arity, CommandContext, CommandOutput, PluginBuilder, PluginError,
};

/// Tope del titulo y del cuerpo. Un dialogo no necesita mas, y evita mandar
/// una linea de comandos enorme al sistema.
pub const MAX_TITLE_CHARS: usize = 128;
pub const MAX_TEXT_CHARS: usize = 2048;

/// Cuanto esperamos antes de cerrar el dialogo. Es bloqueante a proposito: el
/// agente se queda esperando a que alguien lo cierre, pero no para siempre.
pub const DIALOG_TIMEOUT: Duration = Duration::from_secs(120);

pub const DEFAULT_TITLE: &str = "chamuko";

/// Backend elegido. Se guarda para poder explicar el resultado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageboxBackend {
    /// Windows: PowerShell con System.Windows.Forms.
    PowerShell,
    /// macOS: `osascript`, que viene con el sistema.
    AppleScript,
    /// GNOME / GTK.
    Zenity,
    /// KDE.
    Kdialog,
    /// X11 clasico.
    Xmessage,
}

impl MessageboxBackend {
    pub fn name(self) -> &'static str {
        match self {
            Self::PowerShell => "powershell",
            Self::AppleScript => "osascript",
            Self::Zenity => "zenity",
            Self::Kdialog => "kdialog",
            Self::Xmessage => "xmessage",
        }
    }
}

/// Un plan: que ejecutar y con que argumentos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageboxPlan {
    pub backend: MessageboxBackend,
    pub program: String,
    pub args: Vec<String>,
}

/// Titulo y cuerpo ya saneados.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub title: String,
    pub text: String,
}

impl Message {
    /// Valida y recorta. Rechaza un mensaje vacio: un dialogo en blanco no le
    /// dice nada a quien lo ve.
    pub fn new(title: &str, text: &str) -> Result<Self, String> {
        let text = sanitize(text);
        if text.trim().is_empty() {
            return Err("messagebox: the message is empty".to_string());
        }
        let title = sanitize(title);
        let title = if title.trim().is_empty() {
            DEFAULT_TITLE.to_string()
        } else {
            title
        };
        Ok(Self {
            title: clamp(&title, MAX_TITLE_CHARS),
            text: clamp(&text, MAX_TEXT_CHARS),
        })
    }

    /// Mensaje de ejemplo, para probar el plugin sin escribir nada.
    pub fn demo() -> Self {
        Self {
            title: DEFAULT_TITLE.to_string(),
            text: "hello from chamuko.\n\nThis dialog was opened by the agent.".to_string(),
        }
    }
}

/// Quita caracteres de control (salvo salto de linea y tabulador) y los NUL.
///
/// Un NUL dentro de un argumento hace fallar el spawn en Unix, y los demas
/// controles pueden romper el parseo del script que construimos.
fn sanitize(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
}

/// Recorta por caracteres, no por bytes: cortar bytes parte un UTF-8.
fn clamp(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_string();
    }
    let kept: String = input.chars().take(max_chars).collect();
    format!("{kept}...")
}

/// Escapa para una cadena PowerShell entre comillas simples.
///
/// Dentro de `'...'` PowerShell no expande variables ni ejecuta nada; el unico
/// caracter especial es la propia comilla simple, que se dobla.
pub fn escape_powershell(input: &str) -> String {
    input.replace('\'', "''")
}

/// Escapa para una cadena AppleScript entre comillas dobles.
///
/// Primero la barra invertida (si no, escapariamos dos veces) y luego la
/// comilla. Los saltos de linea pasan a `\n` para que el script quede en una
/// sola linea.
pub fn escape_applescript(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\t', "\\t")
}

/// Selecciona el backend segun plataforma, herramientas y sesion grafica.
///
/// `available` y `has_display` se inyectan para que los tests no dependan de
/// la maquina.
pub fn plan_messagebox(
    platform: &str,
    message: &Message,
    available: &dyn Fn(&str) -> bool,
    has_display: bool,
) -> Option<MessageboxPlan> {
    match platform {
        "windows" => Some(MessageboxPlan {
            backend: MessageboxBackend::PowerShell,
            program: "powershell".to_string(),
            args: powershell_args(message),
        }),
        "macos" => Some(MessageboxPlan {
            backend: MessageboxBackend::AppleScript,
            program: "osascript".to_string(),
            args: applescript_args(message),
        }),
        _ => {
            // Sin sesion grafica no hay donde dibujar el dialogo. Mejor decirlo
            // que lanzar un programa que va a fallar por su cuenta.
            if !has_display {
                return None;
            }
            if available("zenity") {
                return Some(MessageboxPlan {
                    backend: MessageboxBackend::Zenity,
                    program: "zenity".to_string(),
                    args: vec![
                        "--info".to_string(),
                        // Sin esto zenity interpreta el texto como marcado Pango
                        // y un `<` desaparece o rompe el dialogo.
                        "--no-markup".to_string(),
                        format!("--title={}", message.title),
                        format!("--text={}", message.text),
                    ],
                });
            }
            if available("kdialog") {
                return Some(MessageboxPlan {
                    backend: MessageboxBackend::Kdialog,
                    program: "kdialog".to_string(),
                    args: vec![
                        "--title".to_string(),
                        message.title.clone(),
                        "--msgbox".to_string(),
                        message.text.clone(),
                    ],
                });
            }
            if available("xmessage") {
                return Some(MessageboxPlan {
                    backend: MessageboxBackend::Xmessage,
                    program: "xmessage".to_string(),
                    args: vec![
                        "-center".to_string(),
                        "-title".to_string(),
                        message.title.clone(),
                        message.text.clone(),
                    ],
                });
            }
            None
        }
    }
}

fn powershell_args(message: &Message) -> Vec<String> {
    let title = escape_powershell(&message.title);
    let text = escape_powershell(&message.text);
    let script = format!(
        "Add-Type -AssemblyName System.Windows.Forms; \
         [System.Windows.Forms.MessageBox]::Show('{text}', '{title}') | Out-Null"
    );
    vec![
        "-NoProfile".to_string(),
        "-NonInteractive".to_string(),
        "-WindowStyle".to_string(),
        "Hidden".to_string(),
        "-Command".to_string(),
        script,
    ]
}

fn applescript_args(message: &Message) -> Vec<String> {
    let title = escape_applescript(&message.title);
    let text = escape_applescript(&message.text);
    // `display alert` da un boton "OK" y no necesita que la app este activa.
    let script = format!(
        "display alert \"{title}\" message \"{text}\" buttons {{\"OK\"}} default button \"OK\""
    );
    vec!["-e".to_string(), script]
}

/// Construye el plugin. Sin argumentos muestra un mensaje de ejemplo; con uno,
/// ese texto; con dos, titulo y texto.
pub fn messagebox_plugin() -> impl chamuko_plugin_api::Plugin {
    PluginBuilder::new("messagebox", "0.1.0")
        .command_with_usage(
            "messagebox",
            "show a dialog on the agent's desktop",
            "messagebox [title] [text]",
            Arity::Between(0, 2),
            run_messagebox,
        )
        .build()
}

/// Resuelve el mensaje y lo muestra.
fn run_messagebox(ctx: &mut CommandContext) -> Result<CommandOutput, PluginError> {
    let message = match message_from(ctx) {
        Ok(m) => m,
        Err(e) => return Ok(CommandOutput::failure(e)),
    };

    let Some(plan) = plan_messagebox(ctx.platform, &message, &which_exists, has_display()) else {
        return Ok(CommandOutput::failure(
            "messagebox: no dialog backend (tried zenity, kdialog, xmessage) or no graphical session",
        ));
    };

    let outcome = chamuko_core::process::run_with_timeout(
        &plan.program,
        &plan.args,
        &ctx.cwd,
        DIALOG_TIMEOUT,
        chamuko_plugin_api::MAX_OUTPUT_BYTES,
    )
    .map_err(|e| format!("messagebox: {e}"))?;

    if outcome.timed_out {
        return Ok(CommandOutput::failure(format!(
            "messagebox: nobody closed the dialog in {}s, it was dismissed",
            DIALOG_TIMEOUT.as_secs()
        )));
    }

    // zenity, kdialog y xmessage devuelven 0 al pulsar el boton. Un codigo
    // distinto de cero suele ser "el usuario cerro la ventana".
    if outcome.exit_code != 0 {
        return Ok(CommandOutput::failure(format!(
            "messagebox: closed without confirming via {} (exit {})",
            plan.backend.name(),
            outcome.exit_code
        )));
    }

    Ok(CommandOutput::new(format!(
        "messagebox shown via {} (title: {:?}, {} chars)",
        plan.backend.name(),
        message.title,
        message.text.chars().count()
    )))
}

fn message_from(ctx: &CommandContext) -> Result<Message, String> {
    match (ctx.arg(0), ctx.arg(1)) {
        (None, _) => Ok(Message::demo()),
        (Some(text), None) => Message::new(DEFAULT_TITLE, text),
        (Some(title), Some(text)) => Message::new(title, text),
    }
}

fn which_exists(program: &str) -> bool {
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&paths).any(|dir| dir.join(program).is_file())
}

/// Una sesion grafica se anuncia por variable de entorno. En Wayland no hay
/// `DISPLAY`, asi que hay que mirar las dos.
fn has_display() -> bool {
    std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some()
}

#[cfg(test)]
mod tests;
