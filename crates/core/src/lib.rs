pub mod policy;
pub mod process;

use std::error::Error;
use std::fmt;

use chamuko_plugin_api::{
    CommandContext, CommandOutput, LifecycleEvent, Plugin, PluginError, PluginMetadata,
};
pub use policy::{AuditEntry, AuditLog, Policy, PolicyError};

#[derive(Debug, PartialEq, Eq)]
pub enum RegistrationError {
    EmptyId,
    DuplicateId(&'static str),
    /// Two plugins claiming the same command name would make routing depend on
    /// registration order, so the second one is refused outright.
    DuplicateCommand { command: &'static str, owner: &'static str },
    NoCommands(&'static str),
}

impl fmt::Display for RegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyId => formatter.write_str("plugin ID must not be blank"),
            Self::DuplicateId(id) => write!(formatter, "plugin '{id}' is already registered"),
            Self::DuplicateCommand { command, owner } => write!(
                formatter,
                "command '{command}' is already provided by plugin '{owner}'"
            ),
            Self::NoCommands(id) => write!(formatter, "plugin '{id}' provides no commands"),
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

/// Why a command did not run.
#[derive(Debug, PartialEq, Eq)]
pub enum DispatchError {
    /// No plugin claims the command.
    UnknownCommand(String),
    /// The policy denied it (denylist, or not on the allowlist).
    Denied(String),
}

impl fmt::Display for DispatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCommand(command) => write!(formatter, "unknown command: {command}"),
            Self::Denied(reason) => write!(formatter, "denied: {reason}"),
        }
    }
}

impl Error for DispatchError {}

struct RegisteredPlugin {
    metadata: PluginMetadata,
    plugin: Box<dyn Plugin>,
}

pub struct PluginRegistry {
    plugins: Vec<RegisteredPlugin>,
    /// Command name -> index into `plugins`, so dispatch is a lookup instead of
    /// a scan and collisions are caught at registration time.
    routes: std::collections::HashMap<&'static str, usize>,
    policy: Policy,
    audit: AuditLog,
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
            routes: std::collections::HashMap::new(),
            policy: Policy::default(),
            audit: AuditLog::default(),
        }
    }

    pub fn with_policy(policy: Policy) -> Self {
        Self {
            policy,
            ..Self::new()
        }
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    pub fn audit(&self) -> &AuditLog {
        &self.audit
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

        let names = plugin.command_names();
        if names.is_empty() {
            return Err(RegistrationError::NoCommands(metadata.id));
        }
        for name in &names {
            if let Some(existing) = self.routes.get(name) {
                return Err(RegistrationError::DuplicateCommand {
                    command: name,
                    owner: self.plugins[*existing].metadata.id,
                });
            }
        }

        let index = self.plugins.len();
        for name in names {
            self.routes.insert(name, index);
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

    /// Runs a command through the policy gate, the route table and the audit
    /// log. A denial is recorded just like a success, so the operator can see
    /// what was attempted.
    pub fn execute(
        &mut self,
        command: &str,
        args: &[String],
        cwd: &std::path::Path,
    ) -> Result<CommandOutput, ExecuteError> {
        if let Err(err) = self.policy.check(command) {
            let reason = err.to_string();
            self.audit
                .record(command, args, false, &reason);
            return Err(ExecuteError::Denied(reason));
        }

        let Some(&index) = self.routes.get(command) else {
            self.audit
                .record(command, args, false, "unknown command");
            return Err(ExecuteError::Dispatch(DispatchError::UnknownCommand(
                command.to_string(),
            )));
        };

        let mut ctx = CommandContext::new(command, args.to_vec(), cwd.to_path_buf());
        let plugin_id = self.plugins[index].metadata.id;
        match self.plugins[index].plugin.execute(&mut ctx) {
            Ok(out) => {
                self.audit.record(command, args, true, plugin_id);
                Ok(out)
            }
            Err(e) => {
                self.audit.record(command, args, false, &e.to_string());
                Err(ExecuteError::Plugin(e))
            }
        }
    }

    pub fn supports(&self, command: &str) -> bool {
        self.routes.contains_key(command)
    }

    pub fn supported_commands(&self) -> Vec<&'static str> {
        let mut out: Vec<&'static str> = self.routes.keys().copied().collect();
        out.sort_unstable();
        out
    }

    /// Help text assembled from every plugin, sorted for stable output.
    pub fn help(&self) -> String {
        let mut lines: Vec<(String, String)> = Vec::new();
        for entry in &self.plugins {
            for (usage, summary) in entry.plugin.help_lines() {
                lines.push((usage.to_string(), summary.to_string()));
            }
        }
        lines.sort();
        lines
            .into_iter()
            .map(|(usage, summary)| format!("  {usage:<22} {summary}"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Failure of a full dispatch, split by cause so callers can react differently.
#[derive(Debug)]
pub enum ExecuteError {
    Dispatch(DispatchError),
    Denied(String),
    Plugin(PluginError),
}

impl fmt::Display for ExecuteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dispatch(e) => write!(formatter, "{e}"),
            Self::Denied(reason) => write!(formatter, "denied: {reason}"),
            Self::Plugin(e) => write!(formatter, "{e}"),
        }
    }
}

impl Error for ExecuteError {}

#[cfg(test)]
mod tests;
