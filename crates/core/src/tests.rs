use super::*;
use chamuko_plugin_api::{Arity, CommandOutput, PluginBuilder};

fn plugin_with(commands: &[&'static str]) -> Box<dyn Plugin> {
    let mut builder = PluginBuilder::new("test", "1.0.0");
    for name in commands {
        builder = builder.command(name, "test command", Arity::Any, |_ctx| {
            Ok(CommandOutput::new("ok"))
        });
    }
    Box::new(builder.build())
}

fn run(registry: &mut PluginRegistry, command: &str) -> Result<CommandOutput, ExecuteError> {
    registry.execute(command, &[], std::path::Path::new("."))
}

#[test]
fn registers_a_plugin_and_routes_its_commands() {
    let mut registry = PluginRegistry::new();
    registry.register(plugin_with(&["alpha", "beta"])).unwrap();

    assert_eq!(registry.len(), 1);
    assert!(registry.supports("alpha"));
    assert!(registry.supports("beta"));
    assert!(!registry.supports("gamma"));
    assert_eq!(registry.supported_commands(), vec!["alpha", "beta"]);
}

#[test]
fn rejects_an_empty_plugin_id() {
    let mut registry = PluginRegistry::new();
    let plugin = PluginBuilder::new("   ", "1.0.0")
        .command("x", "x", Arity::Any, |_| Ok(CommandOutput::new("")))
        .build();
    assert_eq!(
        registry.register(Box::new(plugin)).unwrap_err(),
        RegistrationError::EmptyId
    );
}

#[test]
fn rejects_a_duplicate_plugin_id() {
    let mut registry = PluginRegistry::new();
    registry.register(plugin_with(&["a"])).unwrap();
    assert_eq!(
        registry.register(plugin_with(&["b"])).unwrap_err(),
        RegistrationError::DuplicateId("test")
    );
}

#[test]
fn rejects_a_plugin_that_declares_no_commands() {
    let mut registry = PluginRegistry::new();
    let empty = PluginBuilder::new("empty", "1.0.0").build();
    assert_eq!(
        registry.register(Box::new(empty)).unwrap_err(),
        RegistrationError::NoCommands("empty")
    );
}

#[test]
fn rejects_two_plugins_claiming_the_same_command() {
    let mut registry = PluginRegistry::new();
    registry.register(plugin_with(&["shared"])).unwrap();

    let mut second = PluginBuilder::new("other", "1.0.0");
    second = second.command("shared", "clash", Arity::Any, |_| Ok(CommandOutput::new("")));
    let err = registry.register(Box::new(second.build())).unwrap_err();
    assert_eq!(
        err,
        RegistrationError::DuplicateCommand {
            command: "shared",
            owner: "test"
        }
    );
    assert_eq!(registry.len(), 1);
    assert!(run(&mut registry, "shared").is_ok());
}

#[test]
fn unknown_commands_are_reported_as_such() {
    let mut registry = PluginRegistry::new();
    registry.register(plugin_with(&["known"])).unwrap();
    match run(&mut registry, "nope") {
        Err(ExecuteError::Dispatch(DispatchError::UnknownCommand(name))) => {
            assert_eq!(name, "nope")
        }
        other => panic!("expected unknown command, got {other:?}"),
    }
}

#[test]
fn arity_is_enforced_before_the_handler_runs() {
    let mut registry = PluginRegistry::new();
    let plugin = PluginBuilder::new("strict", "1.0.0")
        .command("needs_two", "two args", Arity::Exactly(2), |_| {
            Ok(CommandOutput::new("ran"))
        })
        .build();
    registry.register(Box::new(plugin)).unwrap();

    let err = registry
        .execute("needs_two", &["one".to_string()], std::path::Path::new("."))
        .unwrap_err();
    assert!(err.to_string().contains("usage: needs_two"), "got: {err}");

    let ok = registry
        .execute(
            "needs_two",
            &["one".to_string(), "two".to_string()],
            std::path::Path::new("."),
        )
        .unwrap();
    assert_eq!(ok.stdout, "ran");
}

#[test]
fn policy_denylist_blocks_a_command_and_is_audited() {
    let mut registry = PluginRegistry::with_policy(Policy::permissive().deny(["danger"]));
    registry.register(plugin_with(&["safe", "danger"])).unwrap();

    assert!(run(&mut registry, "safe").is_ok());
    match run(&mut registry, "danger") {
        Err(ExecuteError::Denied(reason)) => assert!(reason.contains("denylist"), "{reason}"),
        other => panic!("expected denial, got {other:?}"),
    }
    assert_eq!(registry.audit().len(), 2);
    assert_eq!(registry.audit().failures().count(), 1);
}

#[test]
fn policy_allowlist_blocks_everything_else() {
    let mut registry = PluginRegistry::with_policy(Policy::allow_only(["allowed"]));
    registry.register(plugin_with(&["allowed", "blocked"])).unwrap();

    assert!(run(&mut registry, "allowed").is_ok());
    match run(&mut registry, "blocked") {
        Err(ExecuteError::Denied(reason)) => assert!(reason.contains("allowlist"), "{reason}"),
        other => panic!("expected denial, got {other:?}"),
    }
}

#[test]
fn deny_wins_over_allow() {
    let policy = Policy::allow_only(["a", "b"]).deny(["b"]);
    assert!(policy.check("a").is_ok());
    assert!(matches!(
        policy.check("b"),
        Err(PolicyError::ExplicitlyDenied(_))
    ));
}

#[test]
fn a_permissive_policy_allows_anything() {
    let policy = Policy::permissive();
    assert!(!policy.is_restricted());
    assert!(policy.check("anything").is_ok());
}

#[test]
fn audit_records_the_plugin_that_handled_the_command() {
    let mut registry = PluginRegistry::new();
    registry.register(plugin_with(&["cmd"])).unwrap();
    run(&mut registry, "cmd").unwrap();

    let entry = registry.audit().entries().next().unwrap();
    assert_eq!(entry.command, "cmd");
    assert!(entry.ok);
    assert_eq!(entry.detail, "test");
}

#[test]
fn audit_does_not_store_argument_values() {
    let mut registry = PluginRegistry::new();
    registry.register(plugin_with(&["login"])).unwrap();
    registry
        .execute(
            "login",
            &["--password=hunter2".to_string()],
            std::path::Path::new("."),
        )
        .unwrap();

    let entry = registry.audit().entries().next().unwrap();
    assert_eq!(entry.arg_count, 1);
    let rendered = format!("{entry:?}");
    assert!(
        !rendered.contains("hunter2"),
        "audit leaked a secret: {rendered}"
    );
}

#[test]
fn audit_is_bounded() {
    let mut log = AuditLog::with_capacity(3);
    for i in 0..10 {
        log.record(&format!("cmd{i}"), &[], true, "test");
    }
    assert_eq!(log.len(), 3);
    let commands: Vec<&str> = log.entries().map(|e| e.command.as_str()).collect();
    assert_eq!(commands, vec!["cmd7", "cmd8", "cmd9"]);
}

#[test]
fn plugin_errors_are_audited_as_failures() {
    let mut registry = PluginRegistry::new();
    let failing = PluginBuilder::new("bad", "1.0.0")
        .command("boom", "always fails", Arity::Any, |_| Err("intentional".into()))
        .build();
    registry.register(Box::new(failing)).unwrap();

    assert!(run(&mut registry, "boom").is_err());
    let entry = registry.audit().entries().next().unwrap();
    assert!(!entry.ok);
    assert!(entry.detail.contains("intentional"));
}

#[test]
fn lifecycle_events_reach_every_plugin() {
    let mut registry = PluginRegistry::new();
    let a = PluginBuilder::new("first", "1.0.0")
        .command("a", "a", Arity::Any, |_| Ok(CommandOutput::new("")))
        .build();
    let b = PluginBuilder::new("second", "1.0.0")
        .command("b", "b", Arity::Any, |_| Ok(CommandOutput::new("")))
        .build();
    registry.register(Box::new(a)).unwrap();
    registry.register(Box::new(b)).unwrap();
    assert_eq!(registry.len(), 2);
    assert!(registry.dispatch(LifecycleEvent::Startup).is_empty());
    assert!(registry.dispatch(LifecycleEvent::Shutdown).is_empty());
}

#[test]
fn help_lists_every_command_with_its_summary() {
    let mut registry = PluginRegistry::new();
    let plugin = PluginBuilder::new("h", "1.0.0")
        .command_with_usage("do", "does a thing", "do <x>", Arity::Exactly(1), |_| {
            Ok(CommandOutput::new(""))
        })
        .build();
    registry.register(Box::new(plugin)).unwrap();

    let help = registry.help();
    assert!(help.contains("do <x>"));
    assert!(help.contains("does a thing"));
}

#[test]
fn a_handler_receives_its_arguments_and_cwd() {
    let mut registry = PluginRegistry::new();
    let plugin = PluginBuilder::new("ctx", "1.0.0")
        .command("echo", "echo args", Arity::Any, |ctx| {
            Ok(CommandOutput::new(format!(
                "{}:{}",
                ctx.cwd.display(),
                ctx.args.join(",")
            )))
        })
        .build();
    registry.register(Box::new(plugin)).unwrap();

    let out = registry
        .execute(
            "echo",
            &["a".to_string(), "b".to_string()],
            std::path::Path::new("/tmp"),
        )
        .unwrap();
    assert_eq!(out.stdout, "/tmp:a,b");
}

#[test]
fn stateful_handlers_keep_state_between_calls() {
    let counter = std::sync::Arc::new(std::sync::Mutex::new(0));
    let handle = std::sync::Arc::clone(&counter);
    let mut registry = PluginRegistry::new();
    let plugin = PluginBuilder::new("stateful", "1.0.0")
        .command("tick", "increment", Arity::Any, move |_| {
            let mut guard = handle.lock().unwrap();
            *guard += 1;
            Ok(CommandOutput::new(guard.to_string()))
        })
        .build();
    registry.register(Box::new(plugin)).unwrap();

    assert_eq!(run(&mut registry, "tick").unwrap().stdout, "1");
    assert_eq!(run(&mut registry, "tick").unwrap().stdout, "2");
}

#[test]
fn arity_descriptions_are_human_readable() {
    assert_eq!(Arity::Exactly(1).describe(), "1 argument");
    assert_eq!(Arity::Exactly(3).describe(), "3 arguments");
    assert!(Arity::AtLeast(2).describe().contains("at least 2"));
    assert!(Arity::Between(1, 4).describe().contains("1 to 4"));
    assert_eq!(Arity::Any.describe(), "any number of arguments");
}

#[test]
fn arity_acceptance_boundaries_are_inclusive() {
    assert!(Arity::Exactly(2).accepts(2));
    assert!(!Arity::Exactly(2).accepts(1));
    assert!(!Arity::Exactly(2).accepts(3));
    assert!(Arity::Between(1, 3).accepts(1));
    assert!(Arity::Between(1, 3).accepts(3));
    assert!(!Arity::Between(1, 3).accepts(4));
    assert!(Arity::AtLeast(0).accepts(0));
}
