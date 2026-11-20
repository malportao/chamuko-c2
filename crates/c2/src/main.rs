use std::process::ExitCode;
use std::sync::{Arc, Mutex};

mod server;
mod state;
mod tui;

use state::State;

struct Args {
    listen: String,
    headless: bool,
    token: Option<String>,
    /// Local file to stage for agents to pull with the `implant` command.
    stage: Option<String>,
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    let state = Arc::new(Mutex::new(State::new()));

    if let Some(path) = &args.stage {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("[c2] cannot read --stage {path}: {e}");
                return ExitCode::FAILURE;
            }
        };
        let name = std::path::Path::new(path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "payload".to_string());
        let transfer = state.lock().unwrap().stage_download(&name, data.clone());
        eprintln!(
            "[c2] staged {name} ({} bytes) as transfer {transfer}",
            data.len()
        );
        eprintln!("[c2] queue it with: implant {transfer} <remote-path>");
    }
    let options = server::Options {
        listen: args.listen.clone(),
        token: args.token.clone(),
    };

    if args.headless {
        if let Err(e) = server::run(state, &options) {
            eprintln!("[c2] server error: {e}");
            return ExitCode::FAILURE;
        }
        return ExitCode::SUCCESS;
    }

    let server_state = Arc::clone(&state);
    let server_handle = std::thread::spawn(move || {
        if let Err(e) = server::run(server_state, &options) {
            eprintln!("[c2] server error: {e}");
        }
    });

    if let Err(e) = tui::run(Arc::clone(&state)) {
        eprintln!("[c2] tui error: {e}");
        drop(server_handle);
        return ExitCode::FAILURE;
    }

    drop(server_handle);
    ExitCode::SUCCESS
}

fn is_loopback(listen: &str) -> bool {
    let host = listen.rsplit_once(':').map_or(listen, |(host, _)| host);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    matches!(host, "localhost" | "127.0.0.1" | "::1") || host.starts_with("127.")
}

fn parse_args() -> Result<Args, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let env_token = std::env::var("CHAMUKO_TOKEN").ok().filter(|t| !t.is_empty());
    parse_args_from(&args, env_token)
}

fn parse_args_from(args: &[String], env_token: Option<String>) -> Result<Args, String> {
    let mut listen = "0.0.0.0:8080".to_string();
    let mut headless = false;
    let mut token = env_token;
    let mut stage: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" | "-l" => {
                i += 1;
                listen = args
                    .get(i)
                    .cloned()
                    .ok_or("--listen requires a value")?;
            }
            "--port" | "-p" => {
                i += 1;
                let port = args.get(i).ok_or("--port requires a value")?;
                listen = format!("0.0.0.0:{port}");
            }
            "--token" | "-t" => {
                i += 1;
                let value = args.get(i).ok_or("--token requires a value")?;
                token = Some(value.clone()).filter(|t| !t.is_empty());
            }
            "--stage" | "-S" => {
                i += 1;
                let value = args.get(i).ok_or("--stage requires a file path")?;
                stage = Some(value.clone());
            }
            "--headless" => headless = true,
            "--help" | "-h" => {
                println!(
                    "chamuko-c2\n\
                     --listen <addr>   bind address (default: 0.0.0.0:8080)\n\
                     --port <port>     shorthand for --listen 0.0.0.0:<port>\n\
                     --token <tok>     require this bearer token on every API call\n\
                                       (default: $CHAMUKO_TOKEN)\n\
                     --stage <file>    stage a file for agents to pull (implant)\n\
                     --headless        run without the TUI\n\
                     --help            show this help"
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
        i += 1;
    }

    if token.is_none() && !is_loopback(&listen) {
        return Err(format!(
            "refusing to listen on {listen} without a token: pass --token <tok> or set CHAMUKO_TOKEN.\n\
             Use --listen 127.0.0.1:<port> for an unauthenticated local instance."
        ));
    }

    Ok(Args {
        listen,
        headless,
        token,
        stage,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn loopback_detection() {
        assert!(is_loopback("127.0.0.1:8080"));
        assert!(is_loopback("localhost:8080"));
        assert!(is_loopback("[::1]:8080"));
        assert!(!is_loopback("0.0.0.0:8080"));
        assert!(!is_loopback("192.168.1.10:8080"));
    }

    #[test]
    fn refuses_public_bind_without_token() {
        assert!(parse_args_from(&args(&["--port", "8080"]), None).is_err());
        assert!(parse_args_from(&args(&["--listen", "0.0.0.0:9000"]), None).is_err());
    }

    #[test]
    fn allows_loopback_bind_without_token() {
        let parsed = parse_args_from(&args(&["--listen", "127.0.0.1:9000"]), None).unwrap();
        assert_eq!(parsed.listen, "127.0.0.1:9000");
        assert!(parsed.token.is_none());
    }

    #[test]
    fn accepts_token_from_flag_or_env() {
        let parsed = parse_args_from(&args(&["--token", "abc"]), None).unwrap();
        assert_eq!(parsed.token.as_deref(), Some("abc"));

        let parsed = parse_args_from(&args(&["--port", "8080"]), Some("envtok".to_string())).unwrap();
        assert_eq!(parsed.token.as_deref(), Some("envtok"));
    }

    #[test]
    fn empty_token_flag_falls_back_to_guard() {
        assert!(parse_args_from(&args(&["--token", ""]), None).is_err());
    }
}
