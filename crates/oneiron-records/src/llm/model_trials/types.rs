//! Moved from `crates/oneiron/src/llm/model_trials/types.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::llm::model_trials::types::FrozenTrialCase;
pub use oneiron_verb_wire::llm::model_trials::types::HeldOutSelection;
pub use oneiron_verb_wire::llm::model_trials::types::ModelTrialAction;
pub use oneiron_verb_wire::llm::model_trials::types::ModelTrialExecutionState;
pub use oneiron_verb_wire::llm::model_trials::types::ModelTrialPolicy;
pub use oneiron_verb_wire::llm::model_trials::types::ModelTrialReceipt;
pub use oneiron_verb_wire::llm::model_trials::types::ModelTrialRequest;
pub use oneiron_verb_wire::llm::model_trials::types::PairedQualityInterval;
pub use oneiron_verb_wire::llm::model_trials::types::TrialAdmission;
pub use oneiron_verb_wire::llm::model_trials::types::TrialArm;
pub use oneiron_verb_wire::llm::model_trials::types::TrialArmFailure;
pub use oneiron_verb_wire::llm::model_trials::types::TrialArmKey;
pub use oneiron_verb_wire::llm::model_trials::types::TrialArmOutcome;
pub use oneiron_verb_wire::llm::model_trials::types::TrialArmProgress;
pub use oneiron_verb_wire::llm::model_trials::types::TrialAssessment;
pub use oneiron_verb_wire::llm::model_trials::types::TrialEvidence;
pub use oneiron_verb_wire::llm::model_trials::types::TrialMeasurement;
pub use oneiron_verb_wire::llm::model_trials::types::TrialQuality;
pub use oneiron_verb_wire::llm::model_trials::types::TrialReading;
pub use oneiron_verb_wire::llm::model_trials::types::TrialSetPin;
use oneiron_verb_wire::llm::registry::backend::PricedModelBackend;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialObservation {
    pub answer: EntityId,
    pub incumbent: TrialReading,
    pub candidate: TrialReading,
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
