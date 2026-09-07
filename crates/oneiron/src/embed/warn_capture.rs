//! Thread-scoped warning capture for embedding tests.

use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub(super) struct WarnCapture {
    messages: Arc<Mutex<Vec<String>>>,
}

impl WarnCapture {
    pub(super) fn messages(&self) -> Vec<String> {
        self.messages.lock().unwrap().clone()
    }

    pub(super) fn with_default<T>(&self, f: impl FnOnce() -> T) -> T {
        // tracing-core 0.1.36's Rebuilder::JustOne uses the registering
        // thread's default, not the sole registered Dispatch. A concurrent
        // thread with no subscriber can therefore cache Interest::never for
        // a warning needed here (or do so via rebuild_interest_cache).
        // Keep two DISTINCT registered dispatches alive throughout capture
        // so registration/rebuilds consult the registry on every thread.
        // This no-op subscriber is never installed as a default; cloning
        // the capture Dispatch or using Dispatch::none would not register
        // a second subscriber. Events still go only to this thread's sink.
        let _other = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
        let dispatch = tracing::Dispatch::new(self.clone());
        tracing::dispatcher::with_default(&dispatch, f)
    }
}

impl tracing::Subscriber for WarnCapture {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.level() == &tracing::Level::WARN
    }

    fn new_span(&self, _attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut message = String::new();
        event.record(&mut MessageVisitor(&mut message));
        self.messages.lock().unwrap().push(message);
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

struct MessageVisitor<'a>(&'a mut String);

impl tracing::field::Visit for MessageVisitor<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0.push_str(&format!("{value:?}"));
        }
    }
}

#[test]
fn capture_survives_registration_and_rebuild_on_another_thread() {
    // One cold callsite, first reached without a subscriber while capture
    // is active on another thread. A serial emit would miss the defect.
    fn emit_warning(message: &str) {
        tracing::warn!("{message}");
    }

    let capture = WarnCapture::default();
    let other_capture = WarnCapture::default();
    capture.with_default(|| {
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    // Dispatch::none does not register another subscriber:
                    // with the old capture this takes Rebuilder::JustOne.
                    tracing::dispatcher::with_default(&tracing::Dispatch::none(), || {
                        emit_warning("uncaptured warning");
                    });
                })
                .join()
                .expect("uncaptured worker");
        });
        assert!(
            capture.messages().is_empty(),
            "another thread must not leak"
        );
        emit_warning("captured after registration");

        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    tracing::dispatcher::with_default(
                        &tracing::Dispatch::none(),
                        tracing::callsite::rebuild_interest_cache,
                    );
                })
                .join()
                .expect("cache rebuild worker");
        });
        emit_warning("captured after rebuild");
        tracing::info!("not a warning");

        // An overlapping capture must remain a separate sink even though
        // registration and interest caching are process-wide.
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    other_capture.with_default(|| emit_warning("other captured warning"));
                })
                .join()
                .expect("captured worker");
        });
        emit_warning("captured after other scope");
    });

    assert_eq!(
        capture.messages(),
        vec![
            "captured after registration",
            "captured after rebuild",
            "captured after other scope",
        ]
    );
    assert_eq!(other_capture.messages(), vec!["other captured warning"]);
}
