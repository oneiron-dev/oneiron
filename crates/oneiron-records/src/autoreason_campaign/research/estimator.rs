//! Moved from `crates/oneiron/src/autoreason_campaign/research/estimator.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_verb_wire::autoreason_campaign::config::CampaignDatasetRef;
pub use oneiron_verb_wire::autoreason_campaign::research::estimator::BranchBelief;
pub use oneiron_verb_wire::autoreason_campaign::research::estimator::PriorRung;
pub use oneiron_verb_wire::autoreason_campaign::research::estimator::PriorSeed;
pub use oneiron_verb_wire::autoreason_campaign::research::estimator::SelectionRanking;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// A benchmark with fewer cases records, but never admits its estimator.
pub const MIN_SELECTION_BENCHMARK_CASES: u64 = 30;

/// One held-out selection benchmark of an estimator version against the DGM
/// parent formula.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionBenchmark {
    pub estimator_version: String,
    /// The held-out benchmark: frozen campaign trees neither formula was
    /// tuned on.
    pub benchmark: CampaignDatasetRef,
    pub cases: u64,
    /// Each formula's score on the benchmark, on one scale, higher better.
    pub dgm_score: f64,
    pub estimator_score: f64,
    pub receipt_refs: Vec<String>,
    pub recorded_at: u64,
}

impl SelectionBenchmark {
    /// A win: enough cases, and the estimator strictly beats DGM.
    #[must_use]
    pub fn won(&self) -> bool {
        self.cases >= MIN_SELECTION_BENCHMARK_CASES && self.estimator_score > self.dgm_score
    }
}
