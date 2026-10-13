use std::io;
use std::sync::{Arc, Mutex};

use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;

use super::*;

const SENTINEL: &str = "sentinel-row-text-51c9";

/// What the production subscriber wrote, kept instead of sent to stdout.
#[derive(Clone, Default)]
pub(crate) struct CapturedSink(Arc<Mutex<Vec<u8>>>);

impl CapturedSink {
    /// The written text with ANSI styling removed.
    pub(crate) fn text(&self) -> String {
        let raw = String::from_utf8_lossy(&self.0.lock().expect("sink")).into_owned();
        let mut plain = String::with_capacity(raw.len());
        let mut chars = raw.chars();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' {
                chars.by_ref().find(|c| *c == 'm');
            } else {
                plain.push(c);
            }
        }
        plain
    }

    /// The production subscriber, writing here.
    pub(crate) fn production_dispatch(&self) -> tracing::Dispatch {
        tracing::Dispatch::new(subscriber(EnvFilter::new("trace"), self.clone()))
    }

    /// Runs `f` with the production subscriber, writing here, as this
    /// thread's default.
    pub(crate) fn with_production_subscriber<T>(&self, f: impl FnOnce() -> T) -> T {
        tracing::dispatcher::with_default(&self.production_dispatch(), f)
    }
}

impl io::Write for CapturedSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("sink").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'w> MakeWriter<'w> for CapturedSink {
    type Writer = Self;

    fn make_writer(&'w self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn a_panic_reaches_the_log_as_location_and_kind_never_its_payload() {
    // Owner ruling 2026-10-14 (fix 6): crash reports never carry world text.
    // A panic message quoting a row is the realistic leak; the default hook
    // prints it whole.
    let sink = CapturedSink::default();
    let previous = std::panic::take_hook();
    install_panic_hook();
    let caught = std::thread::spawn({
        let sink = sink.clone();
        move || {
            sink.with_production_subscriber(|| {
                std::panic::catch_unwind(|| {
                    panic!("could not parse row body {SENTINEL:?}");
                })
            })
        }
    })
    .join()
    .expect("the panic was caught on its thread");
    std::panic::set_hook(previous);
    assert!(caught.is_err());

    let written = sink.text();
    assert!(
        !written.contains(SENTINEL),
        "panic payload reached the log: {written}"
    );
    assert!(written.contains("payload withheld"), "{written}");
    assert!(
        written.contains(&format!("kind=\"{PANIC_KIND}\"")),
        "{written}"
    );
    assert!(written.contains("logging/tests.rs:"), "{written}");
}
