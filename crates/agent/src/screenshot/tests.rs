use super::*;

fn no_tools(_: &str) -> bool {
    false
}

fn all_tools(_: &str) -> bool {
    true
}

fn only(names: &'static [&'static str]) -> impl Fn(&str) -> bool {
    move |probe| names.contains(&probe)
}

#[test]
fn windows_always_gets_powershell() {
    let plan = plan_capture("windows", PathBuf::from("out.png"), &no_tools).unwrap();
    assert_eq!(plan.backend, Backend::PowerShell);
    assert_eq!(plan.program, "powershell");
    assert!(plan.args.contains(&"-NonInteractive".to_string()));
    assert!(plan.args.contains(&"-NoProfile".to_string()));
    assert!(plan.args.iter().any(|a| a.contains("ImageFormat]::Png")));
}

#[test]
fn windows_script_escapes_single_quotes_in_the_path() {
    let plan = plan_capture(
        "windows",
        PathBuf::from("C:\\Users\\o'brien\\shot.png"),
        &no_tools,
    )
    .unwrap();
    let script = plan.args.last().unwrap();
    assert!(script.contains("o''brien"), "quotes must be doubled: {script}");
    assert!(!script.contains("o'brien'"));
}

#[test]
fn windows_script_uses_the_screen_origin() {
    let plan = plan_capture("windows", PathBuf::from("a.png"), &no_tools).unwrap();
    let script = plan.args.last().unwrap();
    // CopyFromScreen with 0,0 ignores the offset of a secondary monitor.
    assert!(script.contains("CopyFromScreen($b.X, $b.Y, 0, 0"));
    assert!(script.contains("$b.Height"));
}

#[test]
fn macos_uses_screencapture_silently() {
    let plan = plan_capture("macos", PathBuf::from("/tmp/s.png"), &no_tools).unwrap();
    assert_eq!(plan.backend, Backend::Screencapture);
    assert_eq!(plan.program, "screencapture");
    assert_eq!(plan.args[0], "-x");
}

#[test]
fn linux_prefers_grim_over_everything_else() {
    let plan = plan_capture("linux", PathBuf::from("o.png"), &all_tools).unwrap();
    assert_eq!(plan.backend, Backend::Grim);
}

#[test]
fn linux_falls_back_to_scrot_then_import() {
    let scrot = plan_capture("linux", PathBuf::from("o.png"), &only(&["scrot", "import"])).unwrap();
    assert_eq!(scrot.backend, Backend::Scrot);

    let import = plan_capture("linux", PathBuf::from("o.png"), &only(&["import"])).unwrap();
    assert_eq!(import.backend, Backend::ImageMagick);
    assert_eq!(import.args[0], "-window");
    assert_eq!(import.args[1], "root");
}

#[test]
fn linux_uses_the_framebuffer_when_no_tool_exists() {
    let plan = plan_capture("linux", PathBuf::from("o.png"), &only(&["/dev/fb0"])).unwrap();
    assert_eq!(plan.backend, Backend::Framebuffer);
    assert!(plan.program.is_empty());
}

#[test]
fn linux_without_anything_returns_no_plan() {
    assert!(plan_capture("linux", PathBuf::from("o.png"), &no_tools).is_none());
}

#[test]
fn unknown_platforms_are_treated_as_linux() {
    let plan = plan_capture("freebsd", PathBuf::from("o.png"), &only(&["grim"])).unwrap();
    assert_eq!(plan.backend, Backend::Grim);
}

#[test]
fn capture_filename_is_unique_per_stamp_and_ends_in_png() {
    let a = capture_filename(1);
    let b = capture_filename(2);
    assert_ne!(a, b);
    assert!(a.ends_with(".png"));
    assert!(a.starts_with("screenshot-"));
}

#[test]
fn is_png_accepts_a_real_signature_only() {
    let real = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0];
    assert!(is_png(&real));
    assert!(!is_png(b"not a png at all"));
    assert!(!is_png(&real[..4]), "truncated signature must fail");
    assert!(!is_png(b""));
}

#[test]
fn bgra_pixels_become_rgb() {
    let pixels = [
        255, 0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255, 255, 255, 255, 255,
    ];
    let rgb = bgra_to_rgb(&pixels, 32);
    assert_eq!(rgb, vec![0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255, 255]);
}

#[test]
fn rgb24_pixels_are_swapped_not_truncated() {
    let pixels = [1, 2, 3, 4, 5, 6];
    assert_eq!(bgra_to_rgb(&pixels, 24), vec![3, 2, 1, 6, 5, 4]);
}

#[test]
fn rgb565_expands_each_channel() {
    // 0xF800 is pure red in RGB565.
    let rgb = bgra_to_rgb(&[0x00, 0xF8], 16);
    assert_eq!(rgb, vec![0xF8, 0, 0]);
}

#[test]
fn geometry_validates_before_allocating() {
    let ok = FramebufferGeometry {
        width: 1920,
        height: 1080,
        bits_per_pixel: 32,
    };
    assert!(ok.is_sane());
    assert_eq!(ok.stride(), 7680);
    assert_eq!(ok.expected_len(), 1920 * 1080 * 4);

    assert!(!FramebufferGeometry {
        width: 0,
        height: 10,
        bits_per_pixel: 32
    }
    .is_sane());
    assert!(!FramebufferGeometry {
        width: 10,
        height: 10,
        bits_per_pixel: 7
    }
    .is_sane());
    // An absurd geometry must not trigger a giant allocation.
    assert!(!FramebufferGeometry {
        width: 100_000,
        height: 100_000,
        bits_per_pixel: 32
    }
    .is_sane());
}

#[test]
fn geometry_is_read_from_a_sysfs_like_directory() {
    let dir = std::env::temp_dir().join(format!("chamuko-fb-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("virtual_size"), "1024,768\n").unwrap();
    std::fs::write(dir.join("bits_per_pixel"), "32\n").unwrap();

    let geometry = read_framebuffer_geometry(&dir).unwrap();
    assert_eq!(geometry.width, 1024);
    assert_eq!(geometry.height, 768);
    assert_eq!(geometry.bits_per_pixel, 32);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn geometry_reader_rejects_missing_or_garbage_files() {
    let dir = std::env::temp_dir().join(format!("chamuko-fb-bad-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    assert!(read_framebuffer_geometry(&dir).is_none(), "no files at all");

    std::fs::write(dir.join("virtual_size"), "no-comma-here").unwrap();
    std::fs::write(dir.join("bits_per_pixel"), "32").unwrap();
    assert!(read_framebuffer_geometry(&dir).is_none(), "bad virtual_size");

    std::fs::write(dir.join("virtual_size"), "0,0").unwrap();
    assert!(read_framebuffer_geometry(&dir).is_none(), "zero geometry");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn encoded_png_has_a_valid_structure() {
    let png = encode_png(2, 2, &[255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 255]).unwrap();

    assert!(is_png(&png));
    assert!(png.len() > 8 + 25 + 12);

    let width = u32::from_be_bytes([png[16], png[17], png[18], png[19]]);
    let height = u32::from_be_bytes([png[20], png[21], png[22], png[23]]);
    assert_eq!(width, 2);
    assert_eq!(height, 2);
    assert_eq!(png[24], 8, "bit depth");
    assert_eq!(png[25], 2, "colour type RGB");
}

#[test]
fn encoded_png_rejects_wrong_buffer_size() {
    assert!(encode_png(2, 2, &[0, 0, 0]).is_err());
    assert!(encode_png(0, 1, &[]).is_err());
}

#[test]
fn crc32_matches_the_known_ieee_vector() {
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
}

#[test]
fn adler32_matches_the_known_vector() {
    assert_eq!(adler32(b"abc"), 0x024d_0127);
    assert_eq!(adler32(b""), 1);
}

#[test]
fn zlib_stored_splits_large_payloads_into_blocks() {
    let data = vec![7u8; 70_000];
    let wrapped = zlib_stored(&data);
    assert!(wrapped.len() > data.len());
    assert_eq!(&wrapped[..2], &[0x78, 0x01]);
    assert_eq!(wrapped[2] & 1, 0, "first of two blocks is not final");
}

#[test]
fn empty_zlib_payload_is_still_valid() {
    let wrapped = zlib_stored(b"");
    assert_eq!(&wrapped[..2], &[0x78, 0x01]);
    assert_eq!(wrapped[2] & 1, 1, "single empty block must be final");
}

#[test]
fn plugin_advertises_only_the_screenshot_command() {
    let plugin = ScreenshotPlugin::new();
    assert_eq!(plugin.command_names(), vec!["screenshot"]);
    assert_eq!(plugin.metadata().id, "screenshot");
    assert_eq!(plugin.help_lines().len(), 1);
}

#[test]
fn executing_on_a_machine_without_a_display_fails_cleanly() {
    // CI has no display server: the plugin must return a readable error
    // instead of panicking or spawning something that does not exist.
    let mut plugin = ScreenshotPlugin::new();
    let mut ctx = CommandContext::new("screenshot", Vec::new(), std::env::temp_dir());
    ctx.platform = "linux";
    let out = plugin.execute(&mut ctx).unwrap();
    if out.exit_code == 0 {
        let attachment = out.attachment.expect("success must carry a PNG");
        assert!(is_png(&attachment.data));
    } else {
        assert!(out.stdout.contains("screenshot:"), "got: {}", out.stdout);
        assert!(out.attachment.is_none());
    }
}

#[test]
fn encoder_output_is_accepted_by_a_third_party_png_reader() {
    // Write a PNG built by our own encoder, then hand it to Python's zlib and
    // struct modules. Checking our output with our own parser would prove
    // nothing about whether the file is actually a valid PNG.
    let dir = std::env::temp_dir().join(format!("chamuko-png-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("probe.png");

    let width = 4u32;
    let height = 3u32;
    let mut rgb = Vec::new();
    for y in 0..height {
        for x in 0..width {
            rgb.extend_from_slice(&[(x * 60) as u8, (y * 80) as u8, 128]);
        }
    }
    let png = encode_png(width, height, &rgb).unwrap();
    std::fs::write(&path, &png).unwrap();

    let script = format!(
        "import struct,zlib,sys\n\
         d=open({:?},'rb').read()\n\
         assert d[:8]==b'\\x89PNG\\r\\n\\x1a\\n', 'bad signature'\n\
         pos=8\n\
         chunks=[]\n\
         while pos<len(d):\n\
         \x20   n=struct.unpack('>I',d[pos:pos+4])[0]\n\
         \x20   t=d[pos+4:pos+8]\n\
         \x20   body=d[pos+8:pos+8+n]\n\
         \x20   crc=struct.unpack('>I',d[pos+8+n:pos+12+n])[0]\n\
         \x20   assert zlib.crc32(t+body)&0xffffffff==crc, 'bad crc for '+t.decode()\n\
         \x20   chunks.append(t)\n\
         \x20   pos+=12+n\n\
         assert chunks[0]==b'IHDR' and chunks[-1]==b'IEND', chunks\n\
         w,h=struct.unpack('>II',d[16:24])\n\
         assert (w,h)==(4,3), (w,h)\n\
         print('ok')\n",
        path.display().to_string()
    );
    let out = std::process::Command::new("python3")
        .arg("-c")
        .arg(&script)
        .output()
        .expect("python3 available");
    assert!(
        out.status.success(),
        "python rejected our PNG: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    std::fs::remove_dir_all(&dir).ok();
}

fn fake_backend(tag: &str, script: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("chamuko-fake-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let program = dir.join("backend.sh");
    std::fs::write(&program, script).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    (dir, program)
}

#[test]
fn a_backend_that_writes_garbage_is_rejected() {
    let (dir, program) = fake_backend("garbage", "#!/bin/sh\necho 'not a png' > \"$1\"\n");
    let output = dir.join("shot.png");
    let plan = CapturePlan {
        backend: Backend::Scrot,
        program: program.display().to_string(),
        args: vec![output.display().to_string()],
        output: output.clone(),
    };

    let out = run_backend(&plan).unwrap();
    assert_eq!(out.exit_code, 1, "garbage must not be accepted");
    assert!(out.stdout.contains("not a PNG"), "got: {}", out.stdout);
    assert!(out.attachment.is_none());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_backend_that_writes_nothing_is_rejected() {
    let (dir, program) = fake_backend("silent", "#!/bin/sh\nexit 1\n");
    let output = dir.join("shot.png");
    let plan = CapturePlan {
        backend: Backend::Scrot,
        program: program.display().to_string(),
        args: vec![output.display().to_string()],
        output: output.clone(),
    };

    let out = run_backend(&plan).unwrap();
    assert_eq!(out.exit_code, 1);
    assert!(out.stdout.contains("left no file"), "got: {}", out.stdout);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_backend_that_writes_a_real_png_is_accepted() {
    let (dir, program) = fake_backend("good", "#!/bin/sh\ncp \"$2\" \"$1\"\n");
    let source = dir.join("source.png");
    let png = encode_png(2, 1, &[1, 2, 3, 4, 5, 6]).unwrap();
    std::fs::write(&source, &png).unwrap();

    let output = dir.join("shot.png");
    let plan = CapturePlan {
        backend: Backend::Scrot,
        program: program.display().to_string(),
        args: vec![output.display().to_string(), source.display().to_string()],
        output: output.clone(),
    };

    let out = run_backend(&plan).unwrap();
    assert_eq!(out.exit_code, 0, "got: {}", out.stdout);
    let attachment = out.attachment.expect("a valid capture must be attached");
    assert_eq!(attachment.data, png);
    assert!(!output.exists(), "the temp file must be cleaned up");
    std::fs::remove_dir_all(&dir).ok();
}
