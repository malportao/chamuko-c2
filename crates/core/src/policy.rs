use std::collections::BTreeSet;

/// Gate in front of every command. Two modes, because a red-team operator
/// wants both: "block these" for known-bad names, and "only these" for a build
/// that should not be able to do anything else.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    allow: Option<BTreeSet<String>>,
    deny: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    NotAllowed(String),
    ExplicitlyDenied(String),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAllowed(command) => {
                write!(formatter, "'{command}' is not on the allowlist")
            }
            Self::ExplicitlyDenied(command) => {
                write!(formatter, "'{command}' is on the denylist")
            }
        }
    }
}

impl std::error::Error for PolicyError {}

impl Policy {
    /// Nothing restricted. The default for a lab build.
    pub fn permissive() -> Self {
        Self::default()
    }

    /// Only these commands may run.
    pub fn allow_only<I, S>(commands: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            allow: Some(commands.into_iter().map(Into::into).collect()),
            deny: BTreeSet::new(),
        }
    }

    /// Everything except these.
    pub fn deny<I, S>(mut self, commands: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for command in commands {
            self.deny.insert(command.into());
        }
        self
    }

    pub fn is_restricted(&self) -> bool {
        self.allow.is_some() || !self.deny.is_empty()
    }

    /// Deny wins over allow, so an operator can carve an exception out of a
    /// broad allowlist without rewriting it.
    pub fn check(&self, command: &str) -> Result<(), PolicyError> {
        if self.deny.contains(command) {
            return Err(PolicyError::ExplicitlyDenied(command.to_string()));
        }
        if let Some(allow) = &self.allow {
            if !allow.contains(command) {
                return Err(PolicyError::NotAllowed(command.to_string()));
            }
        }
        Ok(())
    }
}

/// One executed (or refused) command. Kept in memory and bounded, so a long
/// session cannot grow without limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub command: String,
    pub arg_count: usize,
    pub ok: bool,
    /// Plugin that handled it, or the reason it was refused.
    pub detail: String,
}

#[derive(Debug, Default)]
pub struct AuditLog {
    entries: std::collections::VecDeque<AuditEntry>,
    capacity: usize,
}

impl AuditLog {
    pub const DEFAULT_CAPACITY: usize = 512;

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: std::collections::VecDeque::with_capacity(capacity.min(1024)),
            capacity,
        }
    }

    /// Records an attempt. Argument values are deliberately not stored: they
    /// routinely carry passwords and tokens, and the audit log is not the place
    /// for them.
    pub fn record(&mut self, command: &str, args: &[String], ok: bool, detail: &str) {
        let capacity = if self.capacity == 0 {
            Self::DEFAULT_CAPACITY
        } else {
            self.capacity
        };
        while self.entries.len() >= capacity {
            self.entries.pop_front();
        }
        self.entries.push_back(AuditEntry {
            command: command.to_string(),
            arg_count: args.len(),
            ok,
            detail: detail.to_string(),
        });
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> impl Iterator<Item = &AuditEntry> {
        self.entries.iter()
    }

    pub fn failures(&self) -> impl Iterator<Item = &AuditEntry> {
        self.entries.iter().filter(|e| !e.ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permissive_accepts_everything_and_reports_unrestricted() {
        let policy = Policy::permissive();
        assert!(!policy.is_restricted());
        for command in ["exec", "screenshot", "", "anything"] {
            assert!(policy.check(command).is_ok());
        }
    }

    #[test]
    fn allowlist_admits_only_the_listed_commands() {
        let policy = Policy::allow_only(["ps", "info"]);
        assert!(policy.is_restricted());
        assert!(policy.check("ps").is_ok());
        assert!(policy.check("info").is_ok());
        match policy.check("exec") {
            Err(PolicyError::NotAllowed(command)) => assert_eq!(command, "exec"),
            other => panic!("expected NotAllowed, got {other:?}"),
        }
    }

    #[test]
    fn denylist_blocks_listed_commands_only() {
        let policy = Policy::permissive().deny(["shellcode"]);
        assert!(policy.is_restricted());
        assert!(policy.check("ps").is_ok());
        match policy.check("shellcode") {
            Err(PolicyError::ExplicitlyDenied(command)) => assert_eq!(command, "shellcode"),
            other => panic!("expected ExplicitlyDenied, got {other:?}"),
        }
    }

    #[test]
    fn deny_beats_allow_for_the_same_command() {
        let policy = Policy::allow_only(["a", "b"]).deny(["b"]);
        assert!(policy.check("a").is_ok());
        assert!(matches!(
            policy.check("b"),
            Err(PolicyError::ExplicitlyDenied(_))
        ));
    }

    #[test]
    fn an_empty_allowlist_blocks_everything() {
        let policy = Policy::allow_only(Vec::<String>::new());
        assert!(policy.check("ps").is_err());
        assert!(policy.check("").is_err());
    }

    #[test]
    fn policy_errors_explain_themselves() {
        let denied = Policy::permissive().deny(["x"]);
        assert!(denied.check("x").unwrap_err().to_string().contains("denylist"));

        let limited = Policy::allow_only(["y"]);
        assert!(limited.check("x").unwrap_err().to_string().contains("allowlist"));
    }

    #[test]
    fn audit_keeps_the_newest_entries_when_full() {
        let mut log = AuditLog::with_capacity(2);
        log.record("first", &[], true, "ok");
        log.record("second", &[], false, "bad");
        log.record("third", &[], true, "ok");

        assert_eq!(log.len(), 2);
        let commands: Vec<&str> = log.entries().map(|e| e.command.as_str()).collect();
        assert_eq!(commands, vec!["second", "third"]);
        assert_eq!(log.failures().count(), 1);
    }

    #[test]
    fn audit_records_only_the_argument_count() {
        let mut log = AuditLog::default();
        log.record("cmd", &["secret-token".to_string(), "x".to_string()], true, "ok");

        let entry = log.entries().next().unwrap();
        assert_eq!(entry.arg_count, 2);
        assert!(!format!("{entry:?}").contains("secret-token"));
    }

    #[test]
    fn an_empty_audit_log_reports_zero() {
        let log = AuditLog::default();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
        assert_eq!(log.failures().count(), 0);
    }
}
