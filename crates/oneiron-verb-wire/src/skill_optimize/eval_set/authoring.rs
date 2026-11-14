//! Moved from `crates/oneiron/src/skill_optimize/eval_set/authoring.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::skill_optimize::eval_set::EvalLabelKind;
pub use crate::skill_optimize::eval_set::authoring::apply::CaseDecision;
pub use crate::skill_optimize::eval_set::authoring::apply::EvalAuthoringSkip;
pub use crate::skill_optimize::eval_set::authoring::apply::FamilyDecision;
pub use crate::skill_optimize::eval_set::authoring::executions::EvalAuthoringCaller;
pub use crate::skill_optimize::eval_set::authoring::executions::EvalAuthoringExecuteRequest;
pub use crate::skill_optimize::eval_set::authoring::executions::EvalAuthoringOutcome;
pub use crate::skill_optimize::eval_set::authoring::executions::EvalAuthoringSkillRun;
use crate::skill_optimize::eval_set::cohort::EvalExposureCounts;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// One label fixed code found for a candidate in grounded evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CandidateLabel {
    pub kind: EvalLabelKind,
    /// `amended` or `kept` for an amendment, `preferred` or `not_preferred`
    /// for an owner's pick.
    pub value: String,
    /// The amendment receipt or preference pair it came from.
    pub reference: String,
    pub at: u64,
    /// The candidate's case already holds it.
    pub held: bool,
    /// The rows the label's value was read from, as fixed code found them
    /// (FIX 5761); kept from the skill, which never asserts them.
    #[serde(skip)]
    pub source_rows: Option<Vec<EntityId>>,
}

/// How many of a seat's families have each purpose.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct PurposeCounts {
    pub development: usize,
    pub judge_audit: usize,
    pub sealed_confirmation: usize,
}

/// A sealed family no cohort holds yet: what a cut could take.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct UncutFamily {
    pub family: EntityId,
    pub cases: usize,
    /// The first and last source date of its cases.
    pub first_at: u64,
    pub last_at: u64,
}

/// One cohort of a seat, as the skill reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CohortSummary {
    pub id: EntityId,
    pub from: u64,
    pub until: u64,
    pub reference: bool,
    pub retired: bool,
    pub members: usize,
    pub families: usize,
    pub rubric_revision: String,
    pub exposure: EvalExposureCounts,
}
pub mod apply;
pub mod executions;
