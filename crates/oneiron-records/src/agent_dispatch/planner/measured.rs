//! Moved from `crates/oneiron/src/agent_dispatch/planner/measured.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// What the vault measured for one candidate on one seat: the posterior
/// mean in force, the candidate's own anchored runs (0 = prior only), and
/// the weight in runs the whole estimate carries (own runs plus its prior).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct MeasuredRate {
    pub mean: f64,
    pub own_runs: f64,
    pub weight_runs: f64,
}

impl MeasuredRate {
    /// One width's anchored record, shrunk toward this estimate: `wins` and
    /// `losses` are its weighted outcome mass, `own_runs` the part of it the
    /// candidate measured itself. Only anchored wins and losses count: an
    /// open team is neither.
    fn pooled(self, wins: f64, losses: f64, own_runs: f64) -> Self {
        let weight = self.weight_runs.max(0.0);
        let total = wins + losses + weight;
        if total <= 0.0 {
            return self;
        }
        Self {
            mean: (wins + self.mean * weight) / total,
            own_runs,
            weight_runs: total,
        }
    }
}
