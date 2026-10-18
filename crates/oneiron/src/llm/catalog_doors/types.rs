//! Typed catalog evidence, held-out trials and owner-reviewed role bindings.
use crate::llm::manifest::{ModelBinding, ModelRole};
use crate::llm::model_trials::{
    FrozenTrialCase, ModelTrial, ModelTrialReceipt, ModelTrialRequest, TrialAdmission,
    TrialAssessment,
};
use crate::llm::registry::{CatalogSeed, ModelRegistryRow, ModelScoreDiff, ScoreSnapshot};
use crate::{EntityId, ModelId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelCatalogRefresh {
    pub revision: String,
    pub expected_revision: Option<String>,
    pub catalog: CatalogSeed,
    #[serde(default)]
    pub scores: Vec<ScoreSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelCatalogRevision {
    pub revision: String,
    pub previous_revision: Option<String>,
    pub catalog: CatalogSeed,
    pub rows: Vec<ModelRegistryRow>,
    pub score_diffs: Vec<ModelScoreDiff>,
    pub refreshed_at: u64,
}

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
pub struct ModelCatalogChange {
    pub model: ModelId,
    pub previous: Option<ModelRegistryRow>,
    pub current: Option<ModelRegistryRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelCatalogDiff {
    pub from: String,
    pub to: String,
    pub changes: Vec<ModelCatalogChange>,
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
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelTrialView {
    pub catalog_revision: String,
    pub id: EntityId,
    pub request: ModelTrialRequest,
    pub incumbent: crate::llm::registry::PricedModelBackend,
    pub candidate: crate::llm::registry::PricedModelBackend,
    pub nominated_score: f64,
    pub score_fetched_at: u64,
    pub cases: Vec<FrozenTrialCase>,
    pub estimated_cost: f64,
    pub admission: TrialAdmission,
    pub prepared_at: u64,
    pub execution_started: bool,
    pub evidence: Option<ModelTrialEvidence>,
    pub receipt: Option<ModelTrialReceipt>,
}

impl ModelTrialView {
    pub(super) fn of(catalog_revision: String, trial: ModelTrial) -> Self {
        Self {
            catalog_revision,
            id: trial.id,
            request: trial.request,
            incumbent: trial.incumbent,
            candidate: trial.candidate,
            nominated_score: trial.nominated_score,
            score_fetched_at: trial.score_fetched_at,
            cases: trial.cases,
            estimated_cost: trial.estimated_cost,
            admission: trial.admission,
            prepared_at: trial.prepared_at,
            execution_started: trial.execution_started,
            evidence: trial.evidence.map(|value| ModelTrialEvidence {
                measurements_hash: value.measurements_hash,
                incumbent_loss: value.incumbent_loss,
                candidate_loss: value.candidate_loss,
                independent_families: value.independent_families,
                incumbent_cost_per_thousand: value.incumbent_cost_per_thousand,
                candidate_cost_per_thousand: value.candidate_cost_per_thousand,
                trial_cost: value.trial_cost,
            }),
            receipt: trial.receipt,
        }
    }
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
pub struct ModelBindingAccept {
    pub proposal: EntityId,
    #[serde(default)]
    pub teacher_approval: Option<crate::llm::manifest::TeacherProbeApproval>,
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

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelBindingProposal {
    pub id: EntityId,
    pub principal: EntityId,
    pub role: ModelRole,
    pub previous: ModelBinding,
    pub proposed: ModelBinding,
    pub trial: ModelTrialView,
    pub status: ModelBindingStatus,
    pub proposed_at: u64,
    pub settled_at: Option<u64>,
}
