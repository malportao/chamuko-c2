use std::io;
use std::sync::{Arc, Mutex};

use chamuko_plugin_api::PluginResult;

use super::*;

type EventLog = Arc<Mutex<Vec<(&'static str, LifecycleEvent)>>>;

struct RecordingPlugin {
    id: &'static str,
    events: EventLog,
    fail_on: Option<LifecycleEvent>,
}

impl Plugin for RecordingPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            id: self.id,
            version: "0.1.0",
        }
    }

    fn on_event(&mut self, event: LifecycleEvent) -> PluginResult {
        self.events.lock().unwrap().push((self.id, event));
        if self.fail_on == Some(event) {
            return Err(io::Error::other("test plugin failure").into());
        }
        Ok(())
    }
}

fn recording_plugin(id: &'static str, events: &EventLog) -> Box<dyn Plugin> {
    Box::new(RecordingPlugin {
        id,
        events: Arc::clone(events),
        fail_on: None,
    })
}

#[test]
fn starts_empty_without_builtin_plugins() {
    let mut registry = PluginRegistry::new();

    assert!(registry.is_empty());
    assert_eq!(registry.len(), 0);
    assert_eq!(registry.metadata().len(), 0);
    assert!(registry.dispatch(LifecycleEvent::Startup).is_empty());
    assert!(registry.dispatch(LifecycleEvent::Shutdown).is_empty());
}

#[test]
fn exposes_registered_plugin_metadata() {
    let events = EventLog::default();
    let mut registry = PluginRegistry::new();
    registry
        .register(recording_plugin("example", &events))
        .unwrap();

    assert!(!registry.is_empty());
    assert_eq!(registry.len(), 1);
    assert_eq!(
        registry.metadata().collect::<Vec<_>>(),
        vec![PluginMetadata {
            id: "example",
            version: "0.1.0",
        }]
    );
    assert!(events.lock().unwrap().is_empty());
}

#[test]
fn rejects_blank_ids_without_registering_plugins() {
    let events = EventLog::default();
    let mut registry = PluginRegistry::new();

    for id in ["", " ", "\t\n"] {
        assert_eq!(
            registry.register(recording_plugin(id, &events)),
            Err(RegistrationError::EmptyId)
        );
    }
    assert!(registry.is_empty());
}

#[test]
fn rejects_duplicate_ids_without_replacing_original_plugin() {
    let original_events = EventLog::default();
    let duplicate_events = EventLog::default();
    let mut registry = PluginRegistry::new();
    registry
        .register(recording_plugin("example", &original_events))
        .unwrap();

    assert_eq!(
        registry.register(recording_plugin("example", &duplicate_events)),
        Err(RegistrationError::DuplicateId("example"))
    );
    assert_eq!(registry.len(), 1);
    assert!(registry.dispatch(LifecycleEvent::Startup).is_empty());
    assert_eq!(original_events.lock().unwrap().len(), 1);
    assert!(duplicate_events.lock().unwrap().is_empty());
}

#[test]
fn dispatches_events_to_all_plugins_in_registration_order() {
    let events = EventLog::default();
    let mut registry = PluginRegistry::new();
    registry
        .register(recording_plugin("zeta", &events))
        .unwrap();
    registry
        .register(recording_plugin("alpha", &events))
        .unwrap();

    assert!(registry.dispatch(LifecycleEvent::Startup).is_empty());
    assert!(registry.dispatch(LifecycleEvent::Shutdown).is_empty());
    assert_eq!(
        *events.lock().unwrap(),
        vec![
            ("zeta", LifecycleEvent::Startup),
            ("alpha", LifecycleEvent::Startup),
            ("zeta", LifecycleEvent::Shutdown),
            ("alpha", LifecycleEvent::Shutdown),
        ]
    );
}

#[test]
fn collects_failures_without_skipping_other_plugins() {
    let events = EventLog::default();
    let mut registry = PluginRegistry::new();
    registry
        .register(Box::new(RecordingPlugin {
            id: "failing",
            events: Arc::clone(&events),
            fail_on: Some(LifecycleEvent::Startup),
        }))
        .unwrap();
    registry
        .register(recording_plugin("healthy", &events))
        .unwrap();

    let failures = registry.dispatch(LifecycleEvent::Startup);

    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].plugin_id, "failing");
    assert_eq!(failures[0].event, LifecycleEvent::Startup);
    assert_eq!(
        failures[0].source().unwrap().to_string(),
        "test plugin failure"
    );
    assert!(failures[0].to_string().contains("failing"));
    assert_eq!(events.lock().unwrap().len(), 2);
    assert!(registry.dispatch(LifecycleEvent::Shutdown).is_empty());
    assert_eq!(events.lock().unwrap().len(), 4);
}

#[test]
fn reports_every_shutdown_failure() {
    let events = EventLog::default();
    let mut registry = PluginRegistry::new();
    for id in ["first", "second"] {
        registry
            .register(Box::new(RecordingPlugin {
                id,
                events: Arc::clone(&events),
                fail_on: Some(LifecycleEvent::Shutdown),
            }))
            .unwrap();
    }

    assert!(registry.dispatch(LifecycleEvent::Startup).is_empty());
    let failures = registry.dispatch(LifecycleEvent::Shutdown);

    assert_eq!(failures.len(), 2);
    assert_eq!(failures[0].plugin_id, "first");
    assert_eq!(failures[1].plugin_id, "second");
    assert!(
        failures
            .iter()
            .all(|failure| failure.event == LifecycleEvent::Shutdown)
    );
}
