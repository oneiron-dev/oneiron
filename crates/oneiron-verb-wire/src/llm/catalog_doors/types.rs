//! Moved from `crates/oneiron/src/llm/catalog_doors/types.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::llm::model_trials::types::ModelTrialRequest;
use crate::llm::model_trials::types::TrialAssessment;
use oneiron_contracts::entity_id::EntityId;
use oneiron_model::model_binding::ModelBinding;
use oneiron_model::model_binding::ModelRole;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelCatalogGet {
    pub revision: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelCatalogDiffRequest {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelTrialNominate {
    pub catalog_revision: String,
    pub request: ModelTrialRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelTrialRef {
    pub question: EntityId,
    pub trial: EntityId,
}

/// One arm of a trial the owner resends (FIX 10464): the case's answer and
/// which of its two reads.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelTrialArmRef {
    pub question: EntityId,
    pub trial: EntityId,
    pub answer: EntityId,
    pub arm: crate::llm::model_trials::types::TrialArm,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelTrialComplete {
    pub question: EntityId,
    pub trial: EntityId,
    pub assessment: TrialAssessment,
}

/// Paid observations remain internal; public evidence names their immutable
/// hash, both costs and the independent families that qualified the offer.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelTrialEvidence {
    pub measurements_hash: [u8; 32],
    pub incumbent_loss: Option<f64>,
    pub candidate_loss: Option<f64>,
    pub independent_families: usize,
    pub incumbent_cost_per_thousand: f64,
    pub candidate_cost_per_thousand: f64,
    pub trial_cost: f64,
    /// Arms sent with no reading back: while nonzero the costs above are the
    /// known billed spend only, and the comparison is unknown (FIX 9920).
    pub unknown_arms: usize,
    /// Earlier attempts of arms the owner resent: while nonzero the costs
    /// above are the known billed spend only (FIX 10464).
    pub resent_unknown_arms: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelBindingPropose {
    pub question: EntityId,
    pub trial: EntityId,
    pub role: ModelRole,
    pub binding: ModelBinding,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelBindingProposalRef {
    pub proposal: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelBindingRead {
    pub role: ModelRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ModelBindingStatus {
    Proposed,
    Accepted,
    Denied,
}
