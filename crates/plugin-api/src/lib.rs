use std::error::Error;

pub type PluginError = Box<dyn Error + Send + Sync>;
pub type PluginResult = Result<(), PluginError>;

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

    fn supports(&self, _command: &str) -> bool {
        false
    }

    fn supported_commands(&self) -> Vec<&'static str> {
        Vec::new()
    }

    fn execute(
        &mut self,
        command: &str,
        args: &[String],
    ) -> Result<CommandOutput, PluginError> {
        let _ = args;
        Err(format!("plugin does not implement command '{command}'").into())
    }
}
