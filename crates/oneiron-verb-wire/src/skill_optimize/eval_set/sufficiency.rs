//! Moved from `crates/oneiron/src/skill_optimize/eval_set/sufficiency.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// The measurements a card is read from. Every number is supplied by the
/// measuring workflow; the card computes nothing it was not given.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SufficiencyInput {
    /// Independent source families in the set.
    pub families: u32,
    /// Families per floor slice, by slice.
    pub floor_slices: BTreeMap<String, u32>,
    /// The fewest families a floor slice needs: the skill's or the owner's
    /// policy, never a default here.
    pub min_families_per_slice: u32,
    /// The seat's retest noise, the default margin.
    pub retest_noise: Option<f64>,
    /// The owner's margin; it can only be stricter than the noise.
    pub owner_margin: Option<f64>,
    /// Candidate minus incumbent on identical tasks, grouped by family.
    pub paired_interval: Option<(f64, f64)>,
    pub detectable_effect: Option<f64>,
    /// The set or rubric version moved since the incumbent was measured.
    pub set_changed: bool,
    pub rubric_changed: bool,
    /// The seat's unrewarded canary moved apart from the measured axis.
    /// `None` when no canary was measured: the card reads unknown.
    pub canary_diverged: Option<bool>,
}
