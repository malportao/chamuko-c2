//! Contracts for statically linked Chamuko plugins.
//!
//! Plugins receive lifecycle events (startup/shutdown) and may volunteer to
//! handle commands dispatched by the C2. A plugin declares which commands
//! it supports via [`Plugin::supports` and executes them via
//! [`Plugin::execute`].

use std::error::Error;

pub type PluginError = Box<dyn Error + Send + Sync>;
pub type PluginResult = Result<(), PluginError>;

/// Output of a command executed by a plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub stdout: String,
    pub exit_code: i32,
}

impl CommandOutput {
    pub fn new(stdout: impl Into<String>) -> Self {
        Self {
            stdout: stdout.into(),
            exit_code: 0,
        }
    }
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

pub trait Plugin: Send {
    fn metadata(&self) -> PluginMetadata;
    fn on_event(&mut self, event: LifecycleEvent) -> PluginResult;

    /// Returns `true` if this plugin can execute `command`.
    ///
    /// Default implementation returns `false`, which is appropriate for
    /// lifecycle-only plugins.
    fn supports(&self, _command: &str) -> bool {
        false
    }

    /// Returns the list of command names this plugin advertises. Used by the
    /// C2 to show available commands. Plugins may leave this empty and still
    /// answer `supports` dynamically.
    fn supported_commands(&self) -> Vec<&'static str> {
        Vec::new()
    }

    /// Execute `command` with `args`. Only called when [`Self::supports`] returned
    /// `true`.
    ///
    /// Default implementation returns an error.
    fn execute(
        &mut self,
        command: &str,
        args: &[String],
    ) -> Result<CommandOutput, PluginError> {
        let _ = args;
        Err(format!("plugin does not implement command '{command}'").into())
    }
}
