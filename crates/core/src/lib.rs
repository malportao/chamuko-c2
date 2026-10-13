use std::error::Error;
use std::fmt;

use chamuko_plugin_api::{CommandOutput, LifecycleEvent, Plugin, PluginError, PluginMetadata};

#[derive(Debug, PartialEq, Eq)]
pub enum RegistrationError {
    EmptyId,
    DuplicateId(&'static str),
}

impl fmt::Display for RegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyId => formatter.write_str("plugin ID must not be blank"),
            Self::DuplicateId(id) => write!(formatter, "plugin '{id}' is already registered"),
        }
    }
}

impl Error for RegistrationError {}

#[derive(Debug)]
pub struct PluginFailure {
    pub plugin_id: &'static str,
    pub event: LifecycleEvent,
    pub source: PluginError,
}

impl fmt::Display for PluginFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "plugin '{}' failed during {:?}: {}",
            self.plugin_id, self.event, self.source
        )
    }
}

impl Error for PluginFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

struct RegisteredPlugin {
    metadata: PluginMetadata,
    plugin: Box<dyn Plugin>,
}

#[derive(Default)]
pub struct PluginRegistry {
    plugins: Vec<RegisteredPlugin>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, plugin: Box<dyn Plugin>) -> Result<(), RegistrationError> {
        let metadata = plugin.metadata();
        if metadata.id.trim().is_empty() {
            return Err(RegistrationError::EmptyId);
        }
        if self
            .plugins
            .iter()
            .any(|entry| entry.metadata.id == metadata.id)
        {
            return Err(RegistrationError::DuplicateId(metadata.id));
        }
        self.plugins.push(RegisteredPlugin { metadata, plugin });
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    pub fn metadata(&self) -> impl ExactSizeIterator<Item = PluginMetadata> + '_ {
        self.plugins.iter().map(|entry| entry.metadata)
    }

    #[must_use]
    pub fn dispatch(&mut self, event: LifecycleEvent) -> Vec<PluginFailure> {
        self.plugins
            .iter_mut()
            .filter_map(|entry| {
                entry
                    .plugin
                    .on_event(event)
                    .err()
                    .map(|source| PluginFailure {
                        plugin_id: entry.metadata.id,
                        event,
                        source,
                    })
            })
            .collect()
    }

    /// Route a command to the first plugin that supports it and return its
    /// output. Returns `None` if no plugin handles the command.
    pub fn execute(
        &mut self,
        command: &str,
        args: &[String],
    ) -> Option<Result<CommandOutput, PluginError>> {
        for entry in self.plugins.iter_mut() {
            if entry.plugin.supports(command) {
                return Some(entry.plugin.execute(command, args));
            }
        }
        None
    }

    /// Returns the list of commands supported by the registered plugins.
    pub fn supported_commands(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        for entry in &self.plugins {
            for cmd in entry.plugin.supported_commands() {
                out.push(cmd);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests;
