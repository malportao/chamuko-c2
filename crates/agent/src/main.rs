use std::process::ExitCode;

use chamuko_core::PluginRegistry;
use chamuko_plugin_api::LifecycleEvent;

fn main() -> ExitCode {
    let mut plugins = PluginRegistry::new();
    let mut failures = plugins.dispatch(LifecycleEvent::Startup);

    println!(
        "chamuko-agent: {} plugins registered; no built-in commands or network transport.",
        plugins.len()
    );

    failures.extend(plugins.dispatch(LifecycleEvent::Shutdown));
    for failure in &failures {
        eprintln!("{failure}");
    }

    if failures.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
