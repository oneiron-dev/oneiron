//! Typed catalog evidence, held-out trials and owner-reviewed role bindings.
use crate::llm::manifest::{ModelBinding, ModelRole};
use crate::llm::model_trials::{
    FrozenTrialCase, ModelTrial, ModelTrialExecutionState, ModelTrialReceipt, ModelTrialRequest,
    TrialAdmission,
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

#[doc(hidden)]
pub use oneiron_verb_wire::llm::catalog_doors::types::{
    ModelBindingProposalRef, ModelBindingPropose, ModelBindingRead, ModelBindingStatus,
    ModelCatalogDiffRequest, ModelCatalogGet, ModelTrialArmRef, ModelTrialComplete,
    ModelTrialEvidence, ModelTrialNominate, ModelTrialRef,
};

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
    /// Where its paid reads stand (FIX 9920): an interrupted trial resumes
    /// the arms never sent on its next run.
    pub execution: ModelTrialExecutionState,
    /// Arms whose billed reading is kept, of `arms_total` (two per case).
    pub arms_completed: usize,
    /// Arms sent with no reading back: their spend is unknown, and they are
    /// never sent again unless the owner resends one (FIX 10464).
    pub arms_unknown: usize,
    /// The arms `arms_unknown` counts, which the owner may resend.
    pub unknown_arms: Vec<crate::llm::model_trials::TrialArmKey>,
    /// Unknown attempts the owner resent: each one's spend stays unknown.
    pub arms_resent: usize,
    pub arms_total: usize,
    pub evidence: Option<ModelTrialEvidence>,
    pub receipt: Option<ModelTrialReceipt>,
}

impl ModelTrialView {
    pub(super) fn of(catalog_revision: String, trial: ModelTrial) -> Self {
        let progress = trial.progress_counts();
        let unknown_arms = trial.unknown_arms();
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
            execution: progress.state,
            arms_completed: progress.completed,
            arms_unknown: progress.unknown,
            unknown_arms,
            arms_resent: progress.resent,
            arms_total: progress.total,
            evidence: trial.evidence.map(|value| ModelTrialEvidence {
                measurements_hash: value.measurements_hash,
                incumbent_loss: value.incumbent_loss,
                candidate_loss: value.candidate_loss,
                independent_families: value.independent_families,
                incumbent_cost_per_thousand: value.incumbent_cost_per_thousand,
                candidate_cost_per_thousand: value.candidate_cost_per_thousand,
                trial_cost: value.trial_cost,
                unknown_arms: value.unknown_arms,
                resent_unknown_arms: value.resent_unknown_arms,
            }),
            receipt: trial.receipt,
        }
    }
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
