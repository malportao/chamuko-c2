use super::*;
use chamuko_plugin_api::Plugin;

fn no_tools(_: &str) -> bool {
    false
}

fn all_tools(_: &str) -> bool {
    true
}

fn only(names: &'static [&'static str]) -> impl Fn(&str) -> bool {
    move |probe| names.contains(&probe)
}

fn msg(text: &str) -> Message {
    Message::new(DEFAULT_TITLE, text).unwrap()
}

#[test]
fn a_demo_message_is_offered_when_no_arguments_are_given() {
    let demo = Message::demo();
    assert_eq!(demo.title, "chamuko");
    assert!(demo.text.contains("hello"));
    assert!(!demo.text.trim().is_empty());
}

#[test]
fn one_argument_becomes_the_body() {
    let mut ctx = CommandContext::new("messagebox", vec!["hola".to_string()], std::env::temp_dir());
    let message = message_from(&ctx).unwrap();
    assert_eq!(message.text, "hola");
    assert_eq!(message.title, DEFAULT_TITLE);

    // And no argument falls back to the demo.
    ctx.args.clear();
    let message = message_from(&ctx).unwrap();
    assert!(message.text.contains("hello"));
}

#[test]
fn two_arguments_are_title_and_body() {
    let ctx = CommandContext::new(
        "messagebox",
        vec!["aviso".to_string(), "cuerpo".to_string()],
        std::env::temp_dir(),
    );
    let message = message_from(&ctx).unwrap();
    assert_eq!(message.title, "aviso");
    assert_eq!(message.text, "cuerpo");
}

#[test]
fn an_empty_message_is_rejected() {
    assert!(Message::new("t", "   ").is_err());
    assert!(Message::new("t", "").is_err());
}

#[test]
fn an_empty_title_falls_back_to_the_default() {
    let message = Message::new("", "cuerpo").unwrap();
    assert_eq!(message.title, DEFAULT_TITLE);
}

#[test]
fn control_characters_are_stripped() {
    // A NUL in an argument makes spawn fail on Unix.
    let message = Message::new("ti\0tulo", "a\0b\x07c").unwrap();
    assert_eq!(message.title, "titulo");
    assert_eq!(message.text, "abc");
}

#[test]
fn newlines_and_tabs_survive_sanitising() {
    let message = Message::new("t", "linea1\nlinea2\ttab").unwrap();
    assert_eq!(message.text, "linea1\nlinea2\ttab");
}

#[test]
fn long_text_is_clamped_by_characters_not_bytes() {
    let long = "ñ".repeat(MAX_TEXT_CHARS + 50);
    let message = Message::new("t", &long).unwrap();
    assert!(message.text.ends_with("..."));
    assert_eq!(message.text.chars().count(), MAX_TEXT_CHARS + 3);
}

#[test]
fn a_long_title_is_clamped() {
    let message = Message::new(&"x".repeat(500), "cuerpo").unwrap();
    assert!(message.title.chars().count() <= MAX_TITLE_CHARS + 3);
}

#[test]
fn windows_always_gets_powershell() {
    let plan = plan_messagebox("windows", &msg("hola"), &no_tools, false).unwrap();
    assert_eq!(plan.backend, MessageboxBackend::PowerShell);
    assert_eq!(plan.program, "powershell");
    assert!(plan.args.contains(&"-NonInteractive".to_string()));
}

#[test]
fn powershell_escaping_doubles_single_quotes() {
    // This is the whole defence: inside '...' PowerShell runs nothing, and a
    // doubled quote stays literal.
    assert_eq!(escape_powershell("it's"), "it''s");
    assert_eq!(escape_powershell("'; rm -rf /; '"), "''; rm -rf /; ''");
    assert_eq!(escape_powershell("$(Get-Process)"), "$(Get-Process)");
}

#[test]
fn a_hostile_message_cannot_break_out_of_the_powershell_string() {
    let hostile = Message::new("t", "'; Remove-Item C:\\ -Recurse; '").unwrap();
    let plan = plan_messagebox("windows", &hostile, &no_tools, false).unwrap();
    let script = plan.args.last().unwrap();

    assert!(script.contains("''; Remove-Item"), "got: {script}");
    let quotes = script.matches('\'').count();
    assert_eq!(
        quotes % 2,
        0,
        "unbalanced quotes mean a broken literal: {script}"
    );
}

#[test]
fn macos_uses_osascript() {
    let plan = plan_messagebox("macos", &msg("hola"), &no_tools, false).unwrap();
    assert_eq!(plan.backend, MessageboxBackend::AppleScript);
    assert_eq!(plan.program, "osascript");
    assert_eq!(plan.args[0], "-e");
    assert!(plan.args[1].contains("display alert"));
}

#[test]
fn applescript_escaping_handles_quotes_and_backslashes() {
    assert_eq!(escape_applescript(r#"say "hi""#), r#"say \"hi\""#);
    // The backslash must be escaped first, otherwise `\"` becomes `\\"`.
    assert_eq!(escape_applescript(r"back\slash"), r"back\\slash");
    assert_eq!(escape_applescript("dos\nlineas"), r"dos\nlineas");
}

#[test]
fn a_hostile_message_cannot_break_out_of_applescript() {
    let hostile = Message::new("t", r#"" & (do shell script "id") & ""#).unwrap();
    let plan = plan_messagebox("macos", &hostile, &no_tools, false).unwrap();
    let script = &plan.args[1];
    assert!(script.contains(r#"\""#), "quotes must be escaped: {script}");
    assert!(
        script.contains(r#"\" & (do shell script \"id\") & \""#),
        "got: {script}"
    );
}

#[test]
fn linux_prefers_zenity_and_disables_markup() {
    let plan = plan_messagebox("linux", &msg("<b>hola</b>"), &all_tools, true).unwrap();
    assert_eq!(plan.backend, MessageboxBackend::Zenity);
    // Without --no-markup, zenity eats the tags and can mangle the dialog.
    assert!(plan.args.contains(&"--no-markup".to_string()));
    assert!(plan.args.iter().any(|a| a == "--text=<b>hola</b>"));
}

#[test]
fn linux_falls_back_to_kdialog_then_xmessage() {
    let kdialog =
        plan_messagebox("linux", &msg("x"), &only(&["kdialog", "xmessage"]), true).unwrap();
    assert_eq!(kdialog.backend, MessageboxBackend::Kdialog);

    let xmessage = plan_messagebox("linux", &msg("x"), &only(&["xmessage"]), true).unwrap();
    assert_eq!(xmessage.backend, MessageboxBackend::Xmessage);
    assert!(xmessage.args.contains(&"-center".to_string()));
}

#[test]
fn linux_without_a_display_refuses_to_try() {
    // No graphical session means no dialog. Returning None is honest; spawning
    // zenity would fail with a confusing GTK error instead.
    assert!(plan_messagebox("linux", &msg("x"), &all_tools, false).is_none());
}

#[test]
fn linux_with_a_display_but_no_tool_returns_none() {
    assert!(plan_messagebox("linux", &msg("x"), &no_tools, true).is_none());
}

#[test]
fn unknown_platforms_are_treated_as_linux() {
    let plan = plan_messagebox("freebsd", &msg("x"), &only(&["zenity"]), true).unwrap();
    assert_eq!(plan.backend, MessageboxBackend::Zenity);
}

#[test]
fn the_plugin_advertises_one_command() {
    let plugin = messagebox_plugin();
    assert_eq!(plugin.command_names(), vec!["messagebox"]);
    assert_eq!(plugin.metadata().id, "messagebox");
    assert_eq!(plugin.help_lines().len(), 1);
    assert!(plugin.help_lines()[0].0.contains("messagebox"));
}

#[test]
fn an_empty_message_fails_cleanly_at_execution() {
    let mut plugin = messagebox_plugin();
    let mut ctx = CommandContext::new("messagebox", vec!["  ".to_string()], std::env::temp_dir());
    let out = plugin.execute(&mut ctx).unwrap();
    assert_eq!(out.exit_code, 1);
    assert!(out.stdout.contains("empty"), "got: {}", out.stdout);
}

#[test]
fn a_headless_machine_reports_the_reason_instead_of_panicking() {
    // CI has no display. Whatever this machine looks like, the plugin must
    // answer with a readable result, never a panic.
    let mut plugin = messagebox_plugin();
    let mut ctx = CommandContext::new("messagebox", Vec::new(), std::env::temp_dir());
    ctx.platform = "linux";
    let out = plugin.execute(&mut ctx).unwrap();

    if out.exit_code == 0 {
        assert!(out.stdout.contains("messagebox shown"));
    } else {
        assert!(out.stdout.contains("messagebox:"), "got: {}", out.stdout);
        assert!(
            out.stdout.contains("no dialog backend") || out.stdout.contains("closed without"),
            "unexpected failure: {}",
            out.stdout
        );
    }
}

#[test]
fn a_dialog_backend_that_exits_non_zero_is_seen_as_failure() {
    // `false` stands in for a dialog the user closed without confirming.
    let outcome = chamuko_core::process::run_with_timeout(
        "false",
        &[],
        &std::env::temp_dir(),
        Duration::from_secs(10),
        chamuko_plugin_api::MAX_OUTPUT_BYTES,
    )
    .unwrap();
    assert_eq!(outcome.exit_code, 1);
    assert!(!outcome.timed_out);
}

#[test]
fn a_dialog_that_is_never_closed_times_out() {
    // `sleep 30` stands in for a dialog nobody closes: the deadline must fire
    // instead of blocking the beacon loop for half a minute.
    let started = std::time::Instant::now();
    let outcome = chamuko_core::process::run_with_timeout(
        "sleep",
        &["30".to_string()],
        &std::env::temp_dir(),
        Duration::from_millis(300),
        chamuko_plugin_api::MAX_OUTPUT_BYTES,
    )
    .unwrap();
    assert!(outcome.timed_out);
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn hostile_text_reaches_the_backend_as_one_single_argument() {
    // On Linux the message is an argv element, never shell-interpreted. Prove
    // it by handing the plan's arguments to `sh -c 'printf ... "$@"'`: the
    // script only prints what it received, so anything split or executed
    // would show up as extra lines.
    let dump = std::env::temp_dir().join(format!("chamuko-argv-{}.txt", std::process::id()));
    let script = format!("printf '%s\\n' \"$@\" > {}", dump.display());

    let hostile = Message::new("t", "$(id); rm -rf /; `whoami` | tee /tmp/pwn").unwrap();
    let plan = plan_messagebox("linux", &hostile, &only(&["zenity"]), true).unwrap();

    let mut args = vec!["-c".to_string(), script, "sh".to_string()];
    args.extend(plan.args.iter().cloned());
    chamuko_core::process::run_with_timeout(
        "/bin/sh",
        &args,
        &std::env::temp_dir(),
        Duration::from_secs(10),
        chamuko_plugin_api::MAX_OUTPUT_BYTES,
    )
    .unwrap();

    let received = std::fs::read_to_string(&dump).unwrap();
    let argv: Vec<&str> = received.lines().collect();

    // Exactly one element per argument: had the text been concatenated into a
    // command line, its spaces and semicolons would have split it apart.
    assert_eq!(
        argv,
        vec![
            "--info",
            "--no-markup",
            "--title=t",
            &format!("--text={}", hostile.text),
        ],
        "the message was split or altered: {argv:?}"
    );
    assert!(!received.contains("uid="), "a subshell executed: {received}");
    std::fs::remove_file(&dump).ok();
}

#[test]
fn a_message_that_looks_like_a_flag_cannot_inject_an_option() {
    // The text is always prefixed with --text=, so a message starting with `-`
    // stays a value and never becomes a zenity option.
    let message = msg("--help");
    let plan = plan_messagebox("linux", &message, &only(&["zenity"]), true).unwrap();
    assert!(plan.args.contains(&"--text=--help".to_string()));
    assert!(!plan.args.contains(&"--help".to_string()));

    let message = msg("-display :0.0 -e touch /tmp/pwn");
    let plan = plan_messagebox("linux", &message, &only(&["zenity"]), true).unwrap();
    assert_eq!(
        plan.args.iter().filter(|a| *a == "-display").count(),
        0,
        "option injection succeeded: {:?}",
        plan.args
    );
}

#[test]
fn the_builder_rejects_too_many_arguments_before_running() {
    // The arity is declared, not hand-checked: a third argument must be
    // refused by the registry before any dialog code runs.
    let mut plugin = messagebox_plugin();
    let mut ctx = CommandContext::new(
        "messagebox",
        vec!["a".to_string(), "b".to_string(), "c".to_string()],
        std::env::temp_dir(),
    );
    let err = plugin.execute(&mut ctx).unwrap_err();
    assert!(
        err.to_string().contains("argument"),
        "expected an arity error, got: {err}"
    );
}
