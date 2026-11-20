use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Result of running a child process under a deadline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessOutcome {
    pub stdout: String,
    pub exit_code: i32,
    pub timed_out: bool,
    pub duration: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessError {
    pub message: String,
}

impl std::fmt::Display for ProcessError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ProcessError {}

/// How long to wait for the reader threads after the child is gone. A
/// grandchild (`sh -c 'a | b'`) can keep the pipe open after the child exits,
/// and joining forever would hang the whole beacon loop.
const READER_GRACE: Duration = Duration::from_secs(2);

/// Runs a program and kills it if it outlives `timeout`.
///
/// Without a deadline, one `sleep 3600` from the operator would block the whole
/// beacon loop and the agent would go dark with no way to recover.
pub fn run_with_timeout(
    program: &str,
    args: &[String],
    cwd: &Path,
    timeout: Duration,
    max_output: usize,
) -> Result<ProcessOutcome, ProcessError> {
    let started = Instant::now();
    let mut child = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| ProcessError {
            message: format!("failed to spawn {program}: {e}"),
        })?;

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let (tx, rx) = mpsc::channel();

    // Read on helper threads so a chatty child cannot fill the pipe and
    // deadlock while we wait for it to exit. Each thread reports through the
    // channel instead of being joined, so a stuck grandchild cannot block us.
    if let Some(pipe) = stdout_pipe {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.take(max_output as u64 + 1).read_to_end(&mut buf);
            let _ = tx.send(Stream::Stdout(buf));
        });
    }
    if let Some(pipe) = stderr_pipe {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.take(max_output as u64 + 1).read_to_end(&mut buf);
            let _ = tx.send(Stream::Stderr(buf));
        });
    }
    drop(tx);

    let mut timed_out = false;
    let exit_code = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.code().unwrap_or(-1),
            Ok(None) => {
                if started.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    break -1;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                let _ = child.kill();
                return Err(ProcessError {
                    message: format!("failed waiting on {program}: {e}"),
                });
            }
        }
    };

    let mut out = Vec::new();
    let mut err = Vec::new();
    let deadline = Instant::now() + READER_GRACE;
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        match rx.recv_timeout(remaining) {
            Ok(Stream::Stdout(buf)) => out = buf,
            Ok(Stream::Stderr(buf)) => err = buf,
            Err(_) => break,
        }
    }

    let mut text = String::from_utf8_lossy(&out).to_string();
    let stderr = String::from_utf8_lossy(&err).to_string();
    if !stderr.is_empty() {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&stderr);
    }
    if timed_out {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&format!(
            "[killed after {}s timeout]",
            timeout.as_secs_f32().round() as u64
        ));
    }

    Ok(ProcessOutcome {
        stdout: chamuko_plugin_api::truncate_output(&text, max_output),
        exit_code,
        timed_out,
        duration: started.elapsed(),
    })
}

enum Stream {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn cwd() -> PathBuf {
        std::env::temp_dir()
    }

    #[test]
    fn runs_a_command_and_captures_stdout() {
        let out = run_with_timeout(
            "echo",
            &["hola".to_string()],
            &cwd(),
            Duration::from_secs(10),
            chamuko_plugin_api::MAX_OUTPUT_BYTES,
        )
        .unwrap();
        assert_eq!(out.stdout.trim(), "hola");
        assert_eq!(out.exit_code, 0);
        assert!(!out.timed_out);
    }

    #[test]
    fn reports_a_non_zero_exit_code_without_failing() {
        let out = run_with_timeout(
            "sh",
            &["-c".to_string(), "exit 7".to_string()],
            &cwd(),
            Duration::from_secs(10),
            chamuko_plugin_api::MAX_OUTPUT_BYTES,
        )
        .unwrap();
        assert_eq!(out.exit_code, 7);
        assert!(!out.timed_out);
    }

    #[test]
    fn merges_stderr_into_the_output() {
        let out = run_with_timeout(
            "sh",
            &["-c".to_string(), "echo out; echo err >&2".to_string()],
            &cwd(),
            Duration::from_secs(10),
            chamuko_plugin_api::MAX_OUTPUT_BYTES,
        )
        .unwrap();
        assert!(out.stdout.contains("out"));
        assert!(out.stdout.contains("err"));
    }

    #[test]
    fn a_missing_program_is_an_error_not_a_panic() {
        let err = run_with_timeout(
            "definitely-not-a-real-program-xyz",
            &[],
            &cwd(),
            Duration::from_secs(5),
            chamuko_plugin_api::MAX_OUTPUT_BYTES,
        )
        .unwrap_err();
        assert!(err.message.contains("failed to spawn"));
    }

    #[test]
    fn a_hung_command_is_killed_at_the_deadline() {
        let started = Instant::now();
        let out = run_with_timeout(
            "sh",
            &["-c".to_string(), "sleep 30".to_string()],
            &cwd(),
            Duration::from_millis(300),
            chamuko_plugin_api::MAX_OUTPUT_BYTES,
        )
        .unwrap();

        assert!(out.timed_out, "the child should have been killed");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the deadline must be enforced, took {:?}",
            started.elapsed()
        );
        assert!(out.stdout.contains("timeout"), "got: {}", out.stdout);
    }

    #[test]
    fn chatty_commands_do_not_flood_memory() {
        let out = run_with_timeout(
            "sh",
            &[
                "-c".to_string(),
                "head -c 200000 /dev/zero | tr '\\0' 'a'".to_string(),
            ],
            &cwd(),
            Duration::from_secs(20),
            1024,
        )
        .unwrap();
        assert!(
            out.stdout.len() < 8192,
            "output should be capped, got {} bytes",
            out.stdout.len()
        );
    }

    #[test]
    fn empty_output_is_fine() {
        let out = run_with_timeout(
            "true",
            &[],
            &cwd(),
            Duration::from_secs(10),
            chamuko_plugin_api::MAX_OUTPUT_BYTES,
        )
        .unwrap();
        assert_eq!(out.exit_code, 0);
        assert!(out.stdout.is_empty());
    }

    #[test]
    fn an_orphan_holding_the_pipe_cannot_hang_the_caller() {
        // The grandchild inherits stdout and outlives the shell. The reader
        // thread stays blocked, so we hit the grace period instead of joining.
        // Known limitation: that output is lost. The important part is that the
        // beacon loop gets control back.
        let started = Instant::now();
        let out = run_with_timeout(
            "sh",
            &[
                "-c".to_string(),
                "echo done; (sleep 30 &) ; exit 0".to_string(),
            ],
            &cwd(),
            Duration::from_secs(5),
            chamuko_plugin_api::MAX_OUTPUT_BYTES,
        )
        .unwrap();
        assert_eq!(out.exit_code, 0);
        assert!(
            started.elapsed() < Duration::from_secs(8),
            "must not wait for the orphaned grandchild, took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_detached_grandchild_with_redirected_fds_still_yields_output() {
        // When the grandchild does not hold our pipe, output arrives normally.
        let started = Instant::now();
        let out = run_with_timeout(
            "sh",
            &[
                "-c".to_string(),
                "echo done; sleep 30 >/dev/null 2>&1 & exit 0".to_string(),
            ],
            &cwd(),
            Duration::from_secs(5),
            chamuko_plugin_api::MAX_OUTPUT_BYTES,
        )
        .unwrap();
        assert_eq!(out.exit_code, 0);
        assert!(out.stdout.contains("done"), "got: {:?}", out.stdout);
        assert!(
            started.elapsed() < Duration::from_secs(8),
            "took {:?}",
            started.elapsed()
        );
    }
}
