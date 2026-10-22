//! Feedback-mode counts: how often agent programs fail a check, which
//! diagnostics they carry, how many and how large, and what their step did
//! next.

use crate::{CheckFailure, CheckReport};
use serde::Serialize;
use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;
use std::time::Duration;

/// What a checked program's step did after its check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepThen {
    /// The program finished its run.
    Completed,
    /// The run parked on a durable wait.
    Waiting,
    /// The program ended without finishing, so another step follows: the
    /// model continues, or repairs, from its observation.
    Continued,
    /// The step failed, and with it the run.
    Failed,
}

impl StepThen {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Waiting => "waiting",
            Self::Continued => "continued",
            Self::Failed => "failed",
        }
    }
}

/// Latency of one backend's checks, over its most recent samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LatencySummary {
    pub samples: usize,
    pub p50_us: u64,
    pub p95_us: u64,
    pub max_us: u64,
}

/// The counts since the process started.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MetricsSnapshot {
    /// Programs a checker answered for.
    pub checked: u64,
    /// Checked programs with at least one diagnostic.
    pub with_diagnostics: u64,
    /// Programs no checker answered for, by failure code.
    pub unchecked: BTreeMap<&'static str, u64>,
    /// Checked programs carrying each diagnostic code: program incidence,
    /// each program counted once per code.
    pub codes: BTreeMap<u32, u64>,
    /// Every diagnostic checked programs carried, each occurrence counted,
    /// partial reports' included.
    pub diagnostic_occurrences: u64,
    /// The UTF-8 bytes of those diagnostics' messages.
    pub diagnostic_bytes: u64,
    /// What the step did next, for programs with diagnostics and without.
    pub then_with_diagnostics: BTreeMap<&'static str, u64>,
    pub then_clean: BTreeMap<&'static str, u64>,
    /// Check latency by backend.
    pub latency: BTreeMap<&'static str, LatencySummary>,
}

/// The samples kept per backend for its percentiles.
const LATENCY_WINDOW: usize = 1024;

#[derive(Default)]
struct Counts {
    snapshot: MetricsSnapshot,
    latency: BTreeMap<&'static str, VecDeque<u64>>,
}

/// Process-lifetime counts of feedback checks.
#[derive(Default)]
pub struct CheckMetrics {
    counts: Mutex<Counts>,
}

impl CheckMetrics {
    /// Counts one program's check and what its step then did, and returns
    /// the counts so far.
    pub fn observe(
        &self,
        result: &Result<CheckReport, CheckFailure>,
        elapsed: Duration,
        then: StepThen,
    ) -> MetricsSnapshot {
        let mut counts = self
            .counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Counts { snapshot, latency } = &mut *counts;
        if let Ok(report) = result {
            snapshot.diagnostic_occurrences = snapshot
                .diagnostic_occurrences
                .saturating_add(report.diagnostics.len() as u64);
            snapshot.diagnostic_bytes = report
                .diagnostics
                .iter()
                .fold(snapshot.diagnostic_bytes, |bytes, diagnostic| {
                    bytes.saturating_add(diagnostic.message.len() as u64)
                });
        }
        match result {
            // A partial report counts as the failure that stopped it.
            Ok(CheckReport {
                incomplete: Some(failure),
                ..
            }) => *snapshot.unchecked.entry(failure.code()).or_default() += 1,
            Ok(report) => {
                snapshot.checked += 1;
                let mut codes: Vec<u32> = report.diagnostics.iter().map(|d| d.code).collect();
                codes.sort_unstable();
                codes.dedup();
                for code in &codes {
                    *snapshot.codes.entry(*code).or_default() += 1;
                }
                let then_counts = if codes.is_empty() {
                    &mut snapshot.then_clean
                } else {
                    snapshot.with_diagnostics += 1;
                    &mut snapshot.then_with_diagnostics
                };
                *then_counts.entry(then.as_str()).or_default() += 1;
                let backend = report.backend.name;
                let samples = latency.entry(backend).or_default();
                if samples.len() == LATENCY_WINDOW {
                    samples.pop_front();
                }
                samples.push_back(u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX));
                snapshot.latency.insert(backend, summary(samples));
            }
            Err(failure) => *snapshot.unchecked.entry(failure.code()).or_default() += 1,
        }
        snapshot.clone()
    }

    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        self.counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .snapshot
            .clone()
    }
}

fn summary(samples: &VecDeque<u64>) -> LatencySummary {
    let mut sorted: Vec<u64> = samples.iter().copied().collect();
    sorted.sort_unstable();
    let at = |quantile: usize| sorted[(sorted.len() * quantile).div_ceil(100).saturating_sub(1)];
    LatencySummary {
        samples: sorted.len(),
        p50_us: at(50),
        p95_us: at(95),
        max_us: sorted.last().copied().unwrap_or(0),
    }
}
