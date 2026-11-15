//! The held-out selection and sufficiency card are supplied by eval authoring.

use crate::EntityId;
use crate::llm::registry::PricedModelBackend;
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_verb_wire::llm::model_trials::types::{
    FrozenTrialCase, HeldOutSelection, ModelTrialAction, ModelTrialExecutionState,
    ModelTrialPolicy, ModelTrialReceipt, ModelTrialRequest, PairedQualityInterval, TrialAdmission,
    TrialArm, TrialArmFailure, TrialArmKey, TrialArmOutcome, TrialArmProgress, TrialAssessment,
    TrialEvidence, TrialMeasurement, TrialQuality, TrialReading, TrialSetPin,
};

/// The replay input deliberately omits the held-out label and outcome fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrialCaseInput {
    pub answer: EntityId,
    pub unit: EntityId,
    pub source_frontier: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialObservation {
    pub answer: EntityId,
    pub incumbent: TrialReading,
    pub candidate: TrialReading,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelTrial {
    pub id: EntityId,
    pub request: ModelTrialRequest,
    pub nominated_score: f64,
    pub score_fetched_at: u64,
    pub incumbent: PricedModelBackend,
    pub candidate: PricedModelBackend,
    pub cases: Vec<FrozenTrialCase>,
    pub estimated_cost: f64,
    pub admission: TrialAdmission,
    pub prepared_at: u64,
    pub execution_started: bool,
    /// Where its paid reads stand (FIX 9920); see
    /// [`ModelTrial::progress_counts`].
    #[serde(default)]
    pub execution: ModelTrialExecutionState,
    /// The run that last claimed it: each claim takes the next.
    #[serde(default)]
    pub run: u32,
    /// Every arm sent, each kept before the next send.
    #[serde(default)]
    pub arms: Vec<TrialArmProgress>,
    /// Arms of unknown outcome the owner chose to send again (FIX 10464),
    /// each as it stood when resent: its spend stays unknown, never zero.
    #[serde(default)]
    pub resent_arms: Vec<TrialArmProgress>,
    pub evidence: Option<TrialEvidence>,
    pub receipt: Option<ModelTrialReceipt>,
}

/// A picker reads the measured pin beside the current backend price. A pin
/// for one router, serving revision or question cannot qualify another.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendQualityPin {
    pub backend: PricedModelBackend,
    pub question: EntityId,
    pub question_version: u32,
    pub trial: EntityId,
    pub set: TrialSetPin,
    pub brier_loss: f64,
    pub cost_per_thousand: f64,
    pub measured_at: u64,
}
