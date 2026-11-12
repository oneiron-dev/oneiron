//! Moved from `crates/oneiron/src/skill_optimize/eval_set.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::skill_optimize::eval_set::authoring::CandidateLabel;
pub use crate::skill_optimize::eval_set::authoring::CohortSummary;
pub use crate::skill_optimize::eval_set::authoring::PurposeCounts;
pub use crate::skill_optimize::eval_set::authoring::UncutFamily;
pub use crate::skill_optimize::eval_set::authoring::apply::CaseDecision;
pub use crate::skill_optimize::eval_set::authoring::apply::EvalAuthoringReport;
pub use crate::skill_optimize::eval_set::authoring::apply::EvalAuthoringSkip;
pub use crate::skill_optimize::eval_set::authoring::apply::FamilyDecision;
pub use crate::skill_optimize::eval_set::authoring::executions::EvalAuthoringCaller;
pub use crate::skill_optimize::eval_set::authoring::executions::EvalAuthoringExecuteAnswer;
pub use crate::skill_optimize::eval_set::authoring::executions::EvalAuthoringExecuteRequest;
pub use crate::skill_optimize::eval_set::authoring::executions::EvalAuthoringExecution;
pub use crate::skill_optimize::eval_set::authoring::executions::EvalAuthoringOutcome;
pub use crate::skill_optimize::eval_set::authoring::executions::EvalAuthoringSkillRun;
pub use crate::skill_optimize::eval_set::cohort::CohortRetirement;
pub use crate::skill_optimize::eval_set::cohort::EvalCohortRetirementAuthor;
pub use crate::skill_optimize::eval_set::cohort::EvalExposure;
pub use crate::skill_optimize::eval_set::cohort::EvalExposureCounts;
pub use crate::skill_optimize::eval_set::cohort::EvalExposureKind;
pub use crate::skill_optimize::eval_set::cut_audit::AuditCase;
pub use crate::skill_optimize::eval_set::cut_audit::AuditCoverage;
pub use crate::skill_optimize::eval_set::cut_audit::AuditMethodPin;
pub use crate::skill_optimize::eval_set::cut_audit::CoverageGap;
pub use crate::skill_optimize::eval_set::cut_audit::EvalCutAuthor;
pub use crate::skill_optimize::eval_set::cut_audit::NearCopyFlag;
pub use crate::skill_optimize::eval_set::repair_task::EvalRepairAction;
pub use crate::skill_optimize::eval_set::repair_task::EvalRepairGrader;
pub use crate::skill_optimize::eval_set::repair_task::EvalRepairPrecondition;
pub use crate::skill_optimize::eval_set::repair_task::EvalRepairTaskSpec;
pub use crate::skill_optimize::eval_set::repair_task::EvalRepairWorld;
pub use crate::skill_optimize::eval_set::sufficiency::SufficiencyCard;
pub use crate::skill_optimize::eval_set::sufficiency::SufficiencyInput;
pub use crate::skill_optimize::eval_set::sufficiency::SufficiencyVerdict;
pub use crate::skill_optimize::eval_set::sufficiency::UnknownReason;
use oneiron_base::error::Error;
use oneiron_base::error::GateError;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::limit_ask::EngineLimit;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

pub const MAX_NAME_BYTES: usize = 64;

/// What a source family is for, fixed when it is assigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FamilyPurpose {
    /// Search, candidate authoring and rubric fitting read these rows.
    Development,
    /// Judge audits read these rows; nothing is ever fitted on them.
    JudgeAudit,
    /// Sealed confirmation: only a date-cut cohort serves them, counted.
    SealedConfirmation,
}

/// How a case came from its sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DerivationKind {
    /// A past task picked from receipts as it ran.
    Receipt,
    /// A linked failure, its outside repair and the observed outcome.
    Repair,
    Paraphrase,
    Summary,
    Translation,
    Synthetic,
    /// A generated rubric over its parent rows.
    Rubric,
}

/// Where a case's label came from. Outcomes and the owner's picks anchor; a
/// judge's verdict never does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvalLabelKind {
    WorldOutcome,
    OwnerPick,
    AdjudicatedAudit,
    JudgeVerdict,
}

impl EvalLabelKind {
    #[must_use]
    pub const fn anchors(self) -> bool {
        !matches!(self, Self::JudgeVerdict)
    }
}

/// One dated, weighted label on a case. `reference` names the outcome fact,
/// ask or audit it came from.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalLabel {
    pub kind: EvalLabelKind,
    pub value: String,
    pub reference: String,
    pub weight: f64,
    pub at: u64,
    /// The rows the label's value was read from, as fixed code found them
    /// when it was recorded (FIX 5761); `None`, unknown, when its producer
    /// named none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_rows: Option<Vec<EntityId>>,
}
pub mod authoring;
pub mod cohort;
pub mod cut_audit;
pub mod doors;
pub mod repair_task;
pub mod sufficiency;
