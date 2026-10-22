//! Paired, family-grouped eval measurements (FIX 574, OF-578; ARCH-0053).
//!
//! A measurement is asked for one frozen request: a seat, the exact
//! incumbent and candidate pins, the cohort and its membership digest, the
//! rubric revision, the scorer, the axis and the method. The request's digest
//! keys one row, which moves Pending -> Claimed -> Final, or to Partial with
//! typed reasons. The trusted measuring host claims it, which counts three
//! Candidate exposures of the cohort (incumbent, candidate and the incumbent
//! retest), records each case's three legs, and finishes it: the family
//! estimator runs once over the complete matched set, and the sufficiency
//! card is read from its numbers. Nothing missing is filled with zero, and a
//! Partial row carries no card: "a set too small to judge shows as unknown".

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{EvalSeat, SufficiencyCard};
use crate::compaction::output::OutputRef;
use crate::entity_id::EntityId;

mod doors;
mod finish;
mod statistics;

pub use self::doors::eval_seat_canary;
pub(super) use self::doors::measurement_in_txn;
pub use self::finish::{JUDGE_SCORE_AXIS, JUDGE_SCORE_UNITS};
pub use self::statistics::{EstimateGap, EvalFamilySummary, MeasurementMethodPin};

/// One arm: the exact model a seat would serve, at its serving revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalArmPin {
    pub model: String,
    pub revision: String,
    /// For a skill comparison, the pinned skill content digest. This build
    /// measures model arms only: an arm that names one reads unavailable.
    pub skill_digest: Option<String>,
}

impl EvalArmPin {
    /// `model@revision`, as exposures and retests name the arm.
    #[must_use]
    pub fn label(&self) -> String {
        format!("{}@{}", self.model, self.revision)
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

/// What a measurement is asked for. Every field is frozen into the digest
/// that keys its row: a changed pin, cohort, rubric, scorer or method is
/// another measurement, never this one's card.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalMeasurementRequest {
    /// The decision that waits on it, such as `training_offer`.
    pub decision: String,
    pub seat: EvalSeat,
    pub incumbent: EvalArmPin,
    pub candidate: EvalArmPin,
    pub cohort: EntityId,
    pub membership_digest: String,
    pub rubric_revision: String,
    /// The scorer's revision (the replay judge's algorithm and wording).
    pub scorer: String,
    pub axis: EvalAxisPin,
    pub floor_slices: FloorSlicePolicy,
    /// The seat's declared canary metric; `None` while none is declared.
    pub canary: Option<String>,
    pub method: MeasurementMethodPin,
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
    /// An arm pins skill content; this build measures model arms only.
    SkillArm,
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
    /// It ended without a complete matched set: no card, and final for its
    /// digest.
    Partial {
        reasons: Vec<MeasurementUnavailable>,
    },
    /// The estimator ran and the card was read.
    Final,
}

/// One leg of a case: one arm's answer and its blind score.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalLegRecord {
    /// The stored raw response.
    pub output: Option<OutputRef>,
    /// The leg's own receipt.
    pub receipt: Option<String>,
    /// The provider that answered, as the model ladder stamped it.
    pub served: Option<String>,
    /// The blind score on the measured axis, as the scorer answered it.
    pub score: Option<f64>,
    /// The scorer that answered, `model@version`.
    pub judge: Option<String>,
    pub unavailable: Option<MeasurementUnavailable>,
}

impl EvalLegRecord {
    /// A leg with no number, and why.
    #[must_use]
    pub fn unavailable(reason: MeasurementUnavailable) -> Self {
        Self {
            unavailable: Some(reason),
            ..Self::default()
        }
    }
}

/// One case's three legs on the same task.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalCaseMeasurement {
    pub case: EntityId,
    pub family: EntityId,
    pub stratum: Option<String>,
    /// BLAKE3 of the task every leg was given, as hex.
    pub task_hash: Option<String>,
    pub incumbent: EvalLegRecord,
    pub candidate: EvalLegRecord,
    /// The incumbent again, on the same task: the retest.
    pub retest: EvalLegRecord,
    pub started_at: u64,
    /// `None` while the legs are under way: a resumed measurement reads such
    /// a case as uncertain, never as unpaid.
    pub recorded_at: Option<u64>,
    /// The rows the case, its labels and the task were read from (FIX 5761);
    /// `None` when any is unknown.
    pub source_rows: Option<Vec<EntityId>>,
}

impl EvalCaseMeasurement {
    /// The legs in order: incumbent, candidate, retest.
    #[must_use]
    pub fn legs(&self) -> [&EvalLegRecord; 3] {
        [&self.incumbent, &self.candidate, &self.retest]
    }
}

/// One measurement's row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalMeasurement {
    /// The request digest, as hex.
    pub digest: String,
    pub request: EvalMeasurementRequest,
    pub state: MeasurementState,
    pub requested_at: u64,
    pub claimed_at: Option<u64>,
    pub settled_at: Option<u64>,
    /// The cohort's cases as the claim released them.
    pub members: Vec<EntityId>,
    /// The three Candidate exposures the claim counted: incumbent,
    /// candidate, retest.
    pub exposures: Vec<EntityId>,
    pub cases: Vec<EvalCaseMeasurement>,
    pub families: Vec<EvalFamilySummary>,
    /// The equal-weight mean of family deltas, candidate minus incumbent.
    pub mean_delta: Option<f64>,
    /// Why the estimator drew no interval, when it drew none.
    pub gap: Option<EstimateGap>,
    pub card: Option<SufficiencyCard>,
}
