//! Moved from `crates/oneiron/src/skill_optimize/eval_set/measurement.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::skill_optimize::eval_set::measurement::statistics::EstimateGap;
pub use crate::skill_optimize::eval_set::measurement::statistics::EvalFamilySummary;
pub use crate::skill_optimize::eval_set::measurement::statistics::MeasurementMethodPin;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// One arm: the exact model a seat would serve, at its serving revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalArmPin {
    pub model: String,
    pub revision: String,
    /// For a skill comparison, the pinned skill content digest (hex): the
    /// measuring host loads exactly that content through the pinned-pack
    /// load and answers each leg under it (FIX 10677).
    pub skill_digest: Option<String>,
}

impl EvalArmPin {
    /// `model@revision`, and `+skill:<digest>` for a skill arm, as exposures
    /// and retests name the arm.
    #[must_use]
    pub fn label(&self) -> String {
        match &self.skill_digest {
            Some(digest) => format!("{}@{}+skill:{digest}", self.model, self.revision),
            None => format!("{}@{}", self.model, self.revision),
        }
    }
}

/// Which way a score is better.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScoreDirection {
    HigherIsBetter,
    LowerIsBetter,
}

/// The axis a measurement scores, its direction and its units.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalAxisPin {
    pub axis: String,
    pub direction: ScoreDirection,
    pub units: String,
}

/// The floor slices a set must hold enough families in, as a skill's or the
/// owner's policy declares them. Empty when none is declared.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FloorSlicePolicy {
    /// Case strata that must each hold enough families; one with none counts
    /// zero.
    pub required: BTreeSet<String>,
    pub min_families_per_slice: u32,
    /// The fewest families the whole set needs; the method's floor holds
    /// when it is larger.
    pub min_families: u32,
}

/// Why a leg, a case or a whole measurement has no number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeasurementUnavailable {
    /// The case is not in the claimed release.
    NotReleased,
    /// The cohort's membership, rubric or retirement moved after the request.
    CohortMoved,
    /// The case's task is not one attempt whose Dreamer input reads as JSON.
    UnsupportedTaskPayload,
    /// The case's attempt row is no longer kept.
    TaskGone,
    /// The case carries no anchoring label to score against.
    NoLabel,
    /// The seat names no served model role.
    NoModelRole,
    /// No live skill carries an arm's pinned content any more.
    SkillContentGone,
    /// A live skill carries an arm's pinned content, and its pack does not
    /// load for a measurement: a resident's own skill, one retired or
    /// rejected, a revision that moved under the load, or a package with no
    /// instructions.
    SkillPackRefused,
    /// An arm's registered serving revision is not its pin.
    PinMoved,
    /// This host cannot serve an arm at its exact pin.
    NoExactModelRoute,
    /// The arms' route prompts differ, so the task is not the same.
    InstructionDiffers,
    /// No scorer answered: none is registered, or it abstained or asked.
    NoScorer,
    /// The scorer's revision is not the request's.
    ScorerMoved,
    /// The scorer would read cut evidence.
    CutEvidence,
    /// A leg was sent before an interruption and its outcome is unknown; it
    /// is never paid for twice.
    UncertainLeg,
    /// The generation call failed.
    GenerationFailed,
    /// The measurement's budget ran out.
    BudgetExhausted,
    /// The measurement's clock ran out.
    ClockExhausted,
    /// A case of the set has no settled record.
    IncompleteCase,
}

/// Where a measurement is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeasurementState {
    /// Asked for; nothing counted or paid.
    Pending,
    /// Its exposures are counted and its legs are under way.
    Claimed,
    /// It ended without a complete matched set: no card. Final for its
    /// digest everywhere but the helper gate, which measures it again on
    /// the next request and replaces it when that measurement settles
    /// (`remeasure_partial_eval_measurement`).
    Partial {
        reasons: Vec<MeasurementUnavailable>,
    },
    /// The estimator ran and the card was read.
    Final,
}
pub mod statistics;
