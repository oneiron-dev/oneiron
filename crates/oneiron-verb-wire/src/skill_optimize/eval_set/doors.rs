//! Moved from `crates/oneiron/src/skill_optimize/eval_set/doors.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::skill_optimize::eval_set::DerivationKind;
use crate::skill_optimize::eval_set::FamilyPurpose;
use crate::skill_optimize::eval_set::cohort::EvalExposure;
use crate::skill_optimize::eval_set::cohort::EvalExposureCounts;
use crate::skill_optimize::eval_set::cohort::EvalExposureKind;
pub use crate::skill_optimize::eval_set::doors::cohort_retire::EvalCohortRetireRequest;
pub use crate::skill_optimize::eval_set::doors::label_ask::EvalLabelAskRequest;
use crate::skill_optimize::eval_set::sufficiency::SufficiencyCard;
use crate::skill_optimize::eval_set::sufficiency::SufficiencyInput;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::attempt_id::AttemptId;
use oneiron_store::attempt_state::AttemptState;
use oneiron_store::dreamer_attempt_payload::DreamerAttemptPayload;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalAuthorNowRequest {}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalAuthoringRef {
    pub attempt: EntityId,
}

/// Completion is the host queue's state. A completed pass may author nothing:
/// no available skill, model or valid plan is never a fabricated report.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalAuthoringResult {
    pub attempt: EntityId,
    pub state: AttemptState,
    pub terminal: bool,
    pub last_error: Option<String>,
    /// The kept record of a pass `vault.evals.authoring.execute` requested:
    /// its caller, outcome and report. A nightly or queued-only pass has
    /// none.
    #[serde(default)]
    pub execution: Option<super::EvalAuthoringExecution>,
}

/// The derivation ledger's ids, kinds and dates, without its label values.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalCaseLineage {
    pub case: EntityId,
    pub kind: DerivationKind,
    pub receipts: Vec<String>,
    pub parents: Vec<EntityId>,
    pub stratum: Option<String>,
    pub draw_probability: Option<f64>,
    pub source_at: u64,
    pub recorded_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalCohortRef {
    pub cohort: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalCohortOpenRequest {
    pub cohort: EntityId,
    pub kind: EvalExposureKind,
    pub consumer: String,
    #[serde(default)]
    pub candidate_pin: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalExposureLedger {
    pub cohort: EntityId,
    pub counts: EvalExposureCounts,
    pub servings: Vec<EvalExposure>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalLabelPickRequest {
    pub decision: String,
    pub case: EntityId,
    pub choose_b: bool,
}
pub mod cohort_retire;
pub mod label_ask;
