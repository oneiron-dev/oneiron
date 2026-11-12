//! Moved from `crates/oneiron/src/skill_optimize/eval_set/sufficiency.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::skill_optimize::eval_set::EvalLabel;
use crate::skill_optimize::eval_set::EvalLabelKind;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnknownReason {
    NoRetestNoise,
    NoInterval,
    IntervalSpansMargin,
    TooFewFamilies {
        slice: String,
        families: u32,
    },
    SetChanged,
    RubricChanged,
    CanaryDiverged,
    /// No canary was measured beside the axis.
    NoCanary,
}

impl UnknownReason {
    /// Whether more labelled cases could settle it.
    const fn labels_help(&self) -> bool {
        matches!(
            self,
            Self::NoInterval | Self::IntervalSpansMargin | Self::TooFewFamilies { .. }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SufficiencyVerdict {
    NotWorse,
    Worse,
    Unknown(Vec<UnknownReason>),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SufficiencyCard {
    pub input: SufficiencyInput,
    /// The margin in force: the noise, or the owner's stricter one.
    pub margin: Option<f64>,
    pub verdict: SufficiencyVerdict,
}

impl SufficiencyCard {
    /// Only a not-worse card may let a decision proceed without a person.
    #[must_use]
    pub fn approves(&self) -> bool {
        self.verdict == SufficiencyVerdict::NotWorse
    }
}
