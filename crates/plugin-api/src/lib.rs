use std::error::Error;

pub type PluginError = Box<dyn Error + Send + Sync>;
pub type PluginResult = Result<(), PluginError>;

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
}
