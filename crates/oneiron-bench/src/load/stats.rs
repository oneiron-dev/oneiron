//! Latency summaries: nearest-rank percentiles over completed requests, with
//! failures counted beside them and never folded into the percentiles.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// What one request left behind.
#[derive(Clone, Debug)]
pub(super) struct Sample {
    pub(super) ms: f64,
    /// `None` on success, else a short failure code (HTTP status or error kind).
    pub(super) error: Option<String>,
    /// A recall answer that said it was cut at its deadline.
    pub(super) partial: bool,
    pub(super) items: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(super) struct Summary {
    pub(super) completed: usize,
    pub(super) failed: usize,
    pub(super) failures: BTreeMap<String, usize>,
    pub(super) seconds: f64,
    pub(super) per_second: f64,
    pub(super) latency_status: String,
    pub(super) latency_reason: Option<String>,
    pub(super) p50_ms: Option<f64>,
    pub(super) p95_ms: Option<f64>,
    pub(super) p99_ms: Option<f64>,
    pub(super) max_ms: Option<f64>,
    pub(super) mean_ms: Option<f64>,
    /// Recall only: answers marked partial (cut at their deadline).
    pub(super) partial: usize,
    /// Recall only: answers with no items.
    pub(super) empty: usize,
}

/// Nearest-rank percentile of sorted samples.
fn rank(sorted: &[f64], pct: usize) -> Option<f64> {
    let n = sorted.len();
    (n > 0).then(|| sorted[(n * pct).div_ceil(100).max(1) - 1])
}

impl Summary {
    pub(super) fn below_corpus_floor(mut self, documents: usize) -> Self {
        if documents < 1_000 {
            self.latency_status = "not_measured".into();
            self.latency_reason = Some("corpus_below_1000_documents".into());
            self.p50_ms = None;
            self.p95_ms = None;
            self.p99_ms = None;
            self.max_ms = None;
            self.mean_ms = None;
        }
        self
    }
    pub(super) fn of(samples: &[Sample], seconds: f64) -> Self {
        let mut ok = samples
            .iter()
            .filter(|s| s.error.is_none())
            .map(|s| s.ms)
            .collect::<Vec<_>>();
        ok.sort_by(f64::total_cmp);
        let mut failures = BTreeMap::new();
        for code in samples.iter().filter_map(|s| s.error.as_ref()) {
            *failures.entry(code.clone()).or_insert(0) += 1;
        }
        let completed = ok.len();
        Self {
            completed,
            failed: samples.len() - completed,
            failures,
            seconds,
            per_second: if seconds > 0.0 {
                completed as f64 / seconds
            } else {
                0.0
            },
            latency_status: "measured".into(),
            latency_reason: None,
            p50_ms: rank(&ok, 50),
            p95_ms: rank(&ok, 95),
            p99_ms: rank(&ok, 99),
            max_ms: ok.last().copied(),
            mean_ms: (completed > 0).then(|| ok.iter().sum::<f64>() / completed as f64),
            partial: samples
                .iter()
                .filter(|s| s.error.is_none() && s.partial)
                .count(),
            empty: samples
                .iter()
                .filter(|s| s.error.is_none() && s.items == 0)
                .count(),
        }
    }
}
