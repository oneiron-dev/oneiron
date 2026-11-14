//! Moved from `crates/oneiron/src/skill_optimize/eval_set/doors.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::skill_optimize::eval_set::DerivationKind;
use crate::skill_optimize::eval_set::cohort::EvalExposure;
use crate::skill_optimize::eval_set::cohort::EvalExposureCounts;
use crate::skill_optimize::eval_set::cohort::EvalExposureKind;
pub use crate::skill_optimize::eval_set::doors::cohort_retire::EvalCohortRetireRequest;
pub use crate::skill_optimize::eval_set::doors::label_ask::EvalLabelAskRequest;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalAuthorNowRequest {}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalAuthoringRef {
    pub attempt: EntityId,
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
