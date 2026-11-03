//! Chamuko C2 server entry point.
//!
//! Spawns the HTTP listener in a background thread and runs the red/black
//! Havoc-style TUI on the main thread. Shared state lives behind an
//! `Arc<Mutex<State>>` so both the HTTP handler and the UI can mutate it.
//!
//! With `--headless`, the TUI is skipped and the HTTP server runs directly
//! on the main thread (useful for testing or headless deployments).

use std::process::ExitCode;
use std::sync::{Arc, Mutex};

mod server;
mod state;
mod tui;

use state::State;

struct Args {
    listen: String,
    headless: bool,
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

    if args.headless {
        // Run the HTTP server directly in the main thread.
        if let Err(e) = server::run(state, &args.listen) {
            eprintln!("[c2] server error: {e}");
            return ExitCode::FAILURE;
        }
        return ExitCode::SUCCESS;
    }

    // HTTP server thread.
    let server_state = Arc::clone(&state);
    let server_listen = args.listen.clone();
    let server_handle = std::thread::spawn(move || {
        if let Err(e) = server::run(server_state, &server_listen) {
            eprintln!("[c2] server error: {e}");
        }
    });

    // TUI on the main thread.
    if let Err(e) = tui::run(Arc::clone(&state)) {
        eprintln!("[c2] tui error: {e}");
        drop(server_handle);
        return ExitCode::FAILURE;
    }

    drop(server_handle);
    ExitCode::SUCCESS
}

fn parse_args() -> Result<Args, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut listen = "0.0.0.0:8080".to_string();
    let mut headless = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" | "-l" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    listen = v.clone();
                } else {
                    return Err("--listen requires a value".to_string());
                }
            }
            "--port" | "-p" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    listen = format!("0.0.0.0:{v}");
                } else {
                    return Err("--port requires a value".to_string());
                }
            }
            "--headless" => headless = true,
            "--help" | "-h" => {
                println!(
                    "chamuko-c2\n\
                     --listen <addr>   bind address (default: 0.0.0.0:8080)\n\
                     --port <port>     shorthand for --listen 0.0.0.0:<port>\n\
                     --headless        run without the TUI\n\
                     --help            show this help"
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
        i += 1;
    }
    Ok(Args { listen, headless })
}
