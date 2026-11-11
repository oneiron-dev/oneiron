//! FIX 21929 (brief 21, Dreamer r5): a partition's stage line splits the
//! residual `extract_ms` into the slot's own prefix (`call_ms`), the wait at
//! the window's prefix barrier (`prefix_ready_ms`), the wait behind the
//! earlier slots' finishes (`finish_start_ms`) and the finish's own work
//! (`finish_ms`); with the timed inner stages they sum to the run's wall
//! time. Reaches the stage clock through
//! `oneiron::test_doors::dreamer_stage_line`, built only under
//! `--cfg oneiron_test_support`.
#![cfg(oneiron_test_support)]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use oneiron::test_doors::dreamer_stage_line::{ClosedModelRun, log_closed_stage_line};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

/// The fields of every `oneiron::dreamer::stages` event, as text.
#[derive(Clone, Default)]
struct StageLines(Arc<Mutex<Vec<Vec<(String, String)>>>>);

/// Collects one event's fields.
struct FieldText<'a>(&'a mut Vec<(String, String)>);

impl Visit for FieldText<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0.push((field.name().to_owned(), format!("{value:?}")));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.push((field.name().to_owned(), value.to_string()));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.push((field.name().to_owned(), value.to_owned()));
    }
}

impl Subscriber for StageLines {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        if event.metadata().target() != "oneiron::dreamer::stages" {
            return;
        }
        let mut fields = Vec::new();
        event.record(&mut FieldText(&mut fields));
        self.0.lock().expect("stage lines").push(fields);
    }

    fn enter(&self, _: &Id) {}

    fn exit(&self, _: &Id) {}
}

#[test]
fn stage_line_splits_extract_residual() {
    let lines = StageLines::default();
    let run_started = Instant::now();
    let at = |ms: u64| run_started + Duration::from_millis(ms);
    // r5's generation-3 shape: the slot's own prefix takes 40 s, the window's
    // barrier holds it 30 s more, it waits 50 s behind an earlier slot's
    // finish, then its own finish runs 70 s, 36 s of it in timed stages.
    let run = ClosedModelRun {
        run_started,
        prefix_ended: at(40_000),
        window_prefixes_ended: at(70_000),
        finish_started: at(120_000),
        corrections_ms: 31_000,
        resolve_ms: 4_000,
        gap_ms: 1_000,
        ended: at(190_000),
    };
    tracing::subscriber::with_default(lines.clone(), || {
        log_closed_stage_line(&run, "01a1b4d368ad745090c82deb8fe5169b", "meso");
    });
    let logged = lines.0.lock().expect("stage lines").clone();
    let field = |name: &str| {
        logged.first().and_then(|line| {
            line.iter()
                .find(|(key, _)| key == name)
                .and_then(|(_, value)| value.parse::<u64>().ok())
        })
    };
    let parts = [
        "call_ms",
        "prefix_ready_ms",
        "finish_start_ms",
        "finish_ms",
        "corrections_ms",
        "resolve_ms",
        "gap_ms",
    ]
    .map(field);
    let wall = parts.iter().flatten().sum::<u64>();
    assert_eq!(
        (logged.len(), parts, field("extract_ms"), wall),
        (
            1,
            [
                Some(40_000),
                Some(30_000),
                Some(50_000),
                Some(34_000),
                Some(31_000),
                Some(4_000),
                Some(1_000)
            ],
            Some(154_000),
            190_000
        ),
        "one stage line whose split parts and inner stages sum to the run's wall time"
    );
}
