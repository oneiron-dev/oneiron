//! Moved from `crates/oneiron/src/autoreason_campaign/research/estimator.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// A rung of the cold-start ladder, in the order it seeds a new posterior.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PriorRung {
    User,
    Persona,
    Global,
}

/// One rung's Beta pseudo-counts, read from that level's data, and the
/// receipt naming where they came from. Pinned at bind.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PriorSeed {
    pub rung: PriorRung,
    pub alpha: f64,
    pub beta: f64,
    pub source_ref: String,
}

/// One branch's belief at a round.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BranchBelief {
    pub alpha: f64,
    pub beta: f64,
    /// Posterior mean chance that a child of this branch beats the incumbent.
    pub p_beat: f64,
    /// The expected information, in nats, one more child outcome carries
    /// about that chance.
    pub information_gain: f64,
}

/// Which formula ranked a round's parents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum SelectionRanking {
    /// The DGM parent formula, the shipped floor.
    Dgm,
    /// Information gain first, DGM breaking ties, under an admitted version.
    InformationGain { estimator_version: String },
}
