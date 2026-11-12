use std::env;
use std::path::PathBuf;
use std::process::Command;

use chamuko_plugin_api::{CommandOutput, LifecycleEvent, Plugin, PluginError, PluginMetadata, PluginResult};

pub struct CoreCommands {
    cwd: PathBuf,
}

impl CoreCommands {
    pub fn new() -> Self {
        Self {
            cwd: env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        }
    }

    fn run_shell(&self, args: &[String]) -> Result<CommandOutput, PluginError> {
        if args.is_empty() {
            return Ok(CommandOutput::new("usage: exec <command> [args...]"));
        }

        let output = if cfg!(windows) {
            let joined = args.join(" ");
            Command::new("cmd")
                .args(["/C", &joined])
                .current_dir(&self.cwd)
                .output()
                .map_err(|e| format!("failed to spawn: {e}"))?
        } else {
            let program = &args[0];
            let rest = &args[1..];
            Command::new(program)
                .args(rest)
                .current_dir(&self.cwd)
                .output()
                .map_err(|e| format!("failed to spawn: {e}"))?
        };

        let mut stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        if !stderr.is_empty() {
            if !stdout.is_empty() {
                stdout.push('\n');
            }
            stdout.push_str(&stderr);
        }
        Ok(CommandOutput {
            stdout,
            exit_code: output.status.code().unwrap_or(-1),
        })
    }

    fn change_dir(&mut self, args: &[String]) -> Result<CommandOutput, PluginError> {
        let target = args.first().map(String::as_str).unwrap_or("/");
        let new_path = if cfg!(windows) {
            if target.len() >= 2 && target.as_bytes()[1] == b':' {
                PathBuf::from(target)
            } else {
                self.cwd.join(target)
            }
        } else if target.starts_with('/') {
            PathBuf::from(target)
        } else {
            self.cwd.join(target)
        };
        if !new_path.is_dir() {
            return Ok(CommandOutput {
                stdout: format!("cd: no such directory: {target}"),
                exit_code: 1,
            });
        }
        self.cwd = new_path;
        Ok(CommandOutput::new(self.cwd.display().to_string()))
    }
}

impl Default for CoreCommands {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for CoreCommands {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            id: "core",
            version: "0.1.0",
        }
    }

    fn on_event(&mut self, _event: LifecycleEvent) -> PluginResult {
        Ok(())
    }

    fn supports(&self, command: &str) -> bool {
        matches!(
            command,
            "exec" | "info" | "whoami" | "hostname" | "pwd" | "ls" | "cd" | "help"
        )
    }

    fn supported_commands(&self) -> Vec<&'static str> {
        vec!["exec", "info", "whoami", "hostname", "pwd", "ls", "cd", "help"]
    }

    fn execute(
        &mut self,
        command: &str,
        args: &[String],
    ) -> Result<CommandOutput, PluginError> {
        match command {
            "exec" => self.run_shell(args),
            "info" => {
                let info = chamuko_protocol::AgentInfo::local(String::new());
                let text = format!(
                    "host: {}\nuser: {}\nos:   {} {}\npid:  {}",
                    info.hostname, info.username, info.os, info.arch, info.pid
                );
                Ok(CommandOutput::new(text))
            }
            "whoami" => Ok(CommandOutput::new(
                env::var("USER")
                    .or_else(|_| env::var("USERNAME"))
                    .unwrap_or_else(|_| "unknown".to_string()),
            )),
            "hostname" => Ok(CommandOutput::new(
                env::var("HOSTNAME")
                    .or_else(|_| env::var("COMPUTERNAME"))
                    .unwrap_or_else(|_| "unknown".to_string()),
            )),
            "pwd" => Ok(CommandOutput::new(self.cwd.display().to_string())),
            "ls" => {
                let dir = args
                    .first()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| self.cwd.clone());
                let entries = std::fs::read_dir(&dir)
                    .map_err(|e| format!("ls: {e}"))?;
                let mut names: Vec<String> = entries
                    .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().to_string()))
                    .collect();
                names.sort();
                Ok(CommandOutput::new(names.join("\n")))
            }
            "cd" => self.change_dir(args),
            "help" => Ok(CommandOutput::new(
                "commands:\n  exec <cmd> [args...]  run a shell command\n  info                 show host info\n  whoami               current user\n  hostname             host name\n  pwd                  current directory\n  ls [dir]             list directory\n  cd <dir>             change directory\n  help                 show this help",
            )),
            _ => Err(format!("unknown command: {command}").into()),
        }
    }
}
