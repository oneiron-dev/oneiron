//! Moved from `crates/oneiron/src/learning/doors.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::claim::learning_evidence::EvidenceRow;
pub use crate::claim::learning_predicate::MeasuredLearningPredicate;
use crate::skill_attribution::late_credit::LateCreditReceipt;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::learning_estimate::Estimate;
use oneiron_base::learning_estimate::EstimateLabels;
use oneiron_base::learning_estimate::EstimateValue;
use oneiron_base::learning_estimate::PriorOrigin;
use oneiron_base::learning_estimate::Window;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LearningBetaValue {
    pub alpha: f64,
    pub beta: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LearningMeanValue {
    pub mean: f64,
    pub spread: f64,
}

/// The estimate's form selects the shape of its value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "form", content = "value", rename_all = "snake_case")]
pub enum MeasuredLearningValue {
    Beta(LearningBetaValue),
    Mean(LearningMeanValue),
    Counts(BTreeMap<String, f64>),
}

impl From<EstimateValue> for MeasuredLearningValue {
    fn from(value: EstimateValue) -> Self {
        match value {
            EstimateValue::Beta { alpha, beta } => Self::Beta(LearningBetaValue { alpha, beta }),
            EstimateValue::Mean { mean, spread } => Self::Mean(LearningMeanValue { mean, spread }),
            EstimateValue::Counts { counts } => Self::Counts(counts),
        }
    }
}

/// A prior has the same value shape as the estimate, without another form tag.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum LearningPriorValue {
    Beta(LearningBetaValue),
    Mean(LearningMeanValue),
    Counts(BTreeMap<String, f64>),
}

impl From<EstimateValue> for LearningPriorValue {
    fn from(value: EstimateValue) -> Self {
        match value {
            EstimateValue::Beta { alpha, beta } => Self::Beta(LearningBetaValue { alpha, beta }),
            EstimateValue::Mean { mean, spread } => Self::Mean(LearningMeanValue { mean, spread }),
            EstimateValue::Counts { counts } => Self::Counts(counts),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LearningPriorView {
    pub origin: PriorOrigin,
    pub value: LearningPriorValue,
    pub weight_runs: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
}

/// The engine's estimate, with its derived UNTESTED mark and explicit prior.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MeasuredLearningEstimate {
    #[serde(flatten)]
    pub value: MeasuredLearningValue,
    pub runs: f64,
    pub prior: LearningPriorView,
    pub untested: bool,
    pub of: String,
    pub labels: EstimateLabels,
    pub window: Window,
    pub ver: String,
}

impl From<Estimate> for MeasuredLearningEstimate {
    fn from(estimate: Estimate) -> Self {
        let untested = estimate.untested();
        Self {
            value: estimate.value.into(),
            runs: estimate.runs,
            prior: LearningPriorView {
                origin: estimate.prior.origin,
                value: estimate.prior.value.into(),
                weight_runs: estimate.prior.weight_runs,
                from: estimate.prior.from,
            },
            untested,
            of: estimate.of,
            labels: estimate.labels,
            window: estimate.window,
            ver: estimate.ver.to_string(),
        }
    }
}

/// A stored projector head, including its exact citations and supersession edges.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LearningHeadView {
    pub claim_ref: String,
    pub at: u64,
    pub evidence_receipts: Vec<String>,
    pub supersedes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LearningEvidenceView {
    pub receipt: String,
    pub evidence: EvidenceRow,
}

/// Observe the atomic projection receipt for one anchored attempt outcome.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LearningProjectionRequest {
    pub attempt_receipt: String,
    pub outcome_receipt: String,
    pub axis: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LearningProjectionView {
    /// Absent means no committed projection, not an empty successful projection.
    pub receipt: Option<LateCreditReceipt>,
}

pub fn entity_id(reference: &str) -> Result<EntityId> {
    EntityId::from_hex(reference)
        .map_err(|_| Error::InvalidClaimBody("a learning record reference is an entity id, 32 hex"))
}
