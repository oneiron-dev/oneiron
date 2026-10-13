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

/// Owner ruling 2026-10-14 (fix 6): a blocking worker's panic payload never
/// reaches the error a command returns, which the binary prints to stderr.
/// `init`, `reembed`, serve's slot builders and the Linear bridge all join
/// their workers through `off_runtime`.
#[tokio::test]
async fn a_worker_panic_returns_no_payload_to_the_cli() {
    let error = off_runtime("init", || -> anyhow::Result<()> {
        panic!("could not parse row: sentinel-world-text-6a0e")
    })
    .await
    .expect_err("the worker panicked");
    for shown in [
        format!("{error}"),
        format!("{error:#}"),
        format!("{error:?}"),
    ] {
        assert!(!shown.contains("sentinel-world-text-6a0e"), "{shown}");
    }
    assert_eq!(error.to_string(), "init panicked");
}

/// Owner ruling 2026-10-14 (fix 6): the default receipt sink logs ids, counts
/// and codes. A run's name, a teacher's purpose, a caller's selector and the
/// model a provider says it served are text, so none reaches the log as given.
#[test]
fn the_receipt_log_carries_ids_and_codes_never_run_text() {
    use oneiron::llm::ModelLocality;
    use oneiron::llm::run_admission::{
        LeaseUnit, Payer, PermitFacts, RunEvent, RunReceipt, RunReceiptSink,
    };

    use crate::models::LoggedReceipts;

    let admitted = RunReceipt {
        run: format!("{SENTINEL} nightly digest"),
        revision: 1,
        event: RunEvent::Admitted(Box::new(PermitFacts {
            selector: Some(format!("{SENTINEL} selector")),
            subject: "test/model@v1".to_owned(),
            offer: "offer-1".to_owned(),
            route: "route-1".to_owned(),
            locality: ModelLocality::ThirdParty,
            payer: Payer::Host,
            catalog_revision: None,
            lease: "lease-7a".to_owned(),
            reserved_units: 100,
            unit: LeaseUnit::tokens(),
            allocation: None,
            allocation_reserved_units: None,
            teacher_target: None,
            purpose: Some(format!("summarise {SENTINEL}")),
            rules_enforced: true,
        })),
    };
    let dispatched = RunReceipt {
        run: format!("{SENTINEL} nightly digest"),
        revision: 1,
        event: RunEvent::Dispatched {
            lease: "lease-7a".to_owned(),
            subject: "test/model@v1".to_owned(),
            route: "route-1".to_owned(),
            request_digest: "digest-0f".to_owned(),
            served_model: Some(format!("{SENTINEL} as served")),
            broker_isolation: None,
            answered: true,
        },
    };
    // A callsite registration racing another test can miss one capture; the
    // lease id proves this capture saw the rows.
    for _ in 0..3 {
        let sink = CapturedSink::default();
        sink.with_production_subscriber(|| {
            LoggedReceipts.record(admitted.clone());
            LoggedReceipts.record(dispatched.clone());
        });
        let written = sink.text();
        if written.contains("lease-7a") {
            assert!(!written.contains(SENTINEL), "{written}");
            assert!(written.contains("test/model@v1"), "{written}");
            assert!(written.contains("unrecognised"), "{written}");
            assert!(written.contains("digest-0f"), "{written}");
            return;
        }
    }
    panic!("no receipt row was captured");
}
