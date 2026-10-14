//! Thread-scoped capture of everything `tracing` would write: every event and
//! span at every level, with its target and every field rendered.
//!
//! The no-world-text checks scan this text for a sentinel row string, so it
//! records more than any formatter would print, never less.

use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub(crate) struct LogCapture {
    lines: Arc<Mutex<Vec<String>>>,
}

impl LogCapture {
    /// Every captured event and span, one line each.
    pub(crate) fn lines(&self) -> Vec<String> {
        self.lines.lock().expect("log capture").clone()
    }

    pub(crate) fn with_default<T>(&self, f: impl FnOnce() -> T) -> T {
        // Two distinct registered dispatches keep callsite interest from being
        // cached as "never" by a thread with no subscriber (see
        // `embed::warn_capture`).
        let _other = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
        let dispatch = tracing::Dispatch::new(self.clone());
        tracing::dispatcher::with_default(&dispatch, f)
    }

    /// Panics naming the first captured line that holds `needle`.
    pub(crate) fn assert_absent(&self, needle: &str) {
        let lines = self.lines();
        if let Some(line) = lines.iter().find(|line| line.contains(needle)) {
            panic!("captured log output holds {needle:?}: {line}");
        }
    }

    fn push(&self, kind: &str, metadata: &tracing::Metadata<'_>, fields: String) {
        let line = format!(
            "{kind} {} {} {}{fields}",
            metadata.level(),
            metadata.target(),
            metadata.name()
        );
        self.lines.lock().expect("log capture").push(line);
    }
}

#[derive(Default)]
struct Fields(String);

impl tracing::field::Visit for Fields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let _ = write!(self.0, " {}={value:?}", field.name());
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        let _ = write!(self.0, " {}={value}", field.name());
    }

    fn record_error(
        &mut self,
        field: &tracing::field::Field,
        value: &(dyn std::error::Error + 'static),
    ) {
        let _ = write!(self.0, " {}={value} ({value:?})", field.name());
    }
}

impl tracing::Subscriber for LogCapture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let mut fields = Fields::default();
        attrs.record(&mut fields);
        self.push("span", attrs.metadata(), fields.0);
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        let mut fields = Fields::default();
        values.record(&mut fields);
        self.lines
            .lock()
            .expect("log capture")
            .push(format!("record{}", fields.0));
    }

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        self.push("event", event.metadata(), fields.0);
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}
