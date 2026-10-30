//! Bench-only wall-clock stage timers for one `vault.recall` (L15). This
//! module and its guards ride on bench builds only and never merge.
//!
//! A [`StageGuard`] adds its elapsed nanoseconds under its stage name when
//! it drops; [`record`] adds a span measured by hand. A stage nested inside
//! another is counted inside its parent too. A name starting `count.` holds
//! a count, not nanoseconds: [`record`] carries the count in the nanosecond
//! slot, [`take_json`] writes its sum as `{"n":<sum>}`, and the bench prints
//! `count.*` entries as counts.
//!
//! The accumulator is process-wide: the bench sends one recall at a time.

use std::fmt::Write as _;
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

/// Every span recorded since the last [`take_json`]: (stage name, nanoseconds).
static STAGES: Mutex<Vec<(&'static str, u64)>> = Mutex::new(Vec::new());

/// Spans kept between drains; one recall records well under a hundred.
const MAX_SPANS: usize = 1 << 16;

/// Times one stage from [`stage`] until it drops.
pub struct StageGuard {
    name: &'static str,
    started: Instant,
}

impl Drop for StageGuard {
    fn drop(&mut self) {
        record(
            self.name,
            u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX),
        );
    }
}

/// Starts timing stage `name`; the span ends when the guard drops.
#[must_use = "a stage is timed until its guard drops"]
pub fn stage(name: &'static str) -> StageGuard {
    StageGuard {
        name,
        started: Instant::now(),
    }
}

/// Adds `nanos` under `name`: a span measured by hand, or for a `count.`
/// name, a count.
pub fn record(name: &'static str, nanos: u64) {
    let mut stages = STAGES.lock().unwrap_or_else(PoisonError::into_inner);
    // Traffic with no recall to drain it keeps a bounded tail.
    if stages.len() < MAX_SPANS {
        stages.push((name, nanos));
    }
}

/// Drains the accumulator into compact JSON, one entry per stage name in
/// first-seen order: `{"<name>":{"ms":<sum ms, 3 decimals>,"n":<count>},...}`,
/// and `{"<name>":{"n":<sum>}}` for a `count.` name.
pub fn take_json() -> String {
    let spans = std::mem::take(&mut *STAGES.lock().unwrap_or_else(PoisonError::into_inner));
    let mut totals: Vec<(&'static str, u64, u64)> = Vec::new();
    for (name, value) in spans {
        match totals.iter_mut().find(|(seen, _, _)| *seen == name) {
            Some((_, sum, count)) => {
                *sum = sum.saturating_add(value);
                *count += 1;
            }
            None => totals.push((name, value, 1)),
        }
    }
    let mut json = String::from("{");
    for (index, (name, sum, count)) in totals.into_iter().enumerate() {
        if index > 0 {
            json.push(',');
        }
        // Writing into a String cannot fail.
        let _ = if name.starts_with("count.") {
            write!(json, "\"{name}\":{{\"n\":{sum}}}")
        } else {
            let whole = sum / 1_000_000;
            let micros = (sum / 1_000) % 1_000;
            write!(json, "\"{name}\":{{\"ms\":{whole}.{micros:03},\"n\":{count}}}")
        };
    }
    json.push('}');
    json
}

/// Bench-only A/B switches: `L15_TRY=a,b` in the server's environment turns
/// on the named candidate paths for the life of the process.
pub fn try_on(name: &str) -> bool {
    static ON: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    ON.get_or_init(|| {
        std::env::var("L15_TRY")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect()
    })
    .iter()
    .any(|s| s == name)
}
