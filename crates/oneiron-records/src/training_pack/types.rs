//! Moved from `crates/oneiron/src/training_pack/types.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::llm::run_admission::host::Payer;
pub use crate::skill_optimize::training_choice::ComputeChoice;
pub use crate::skill_optimize::training_choice::TrainingAuthorizationSource;
pub use crate::skill_optimize::training_choice::TrainingState;
use oneiron_contracts::entity_id::EntityId;
use oneiron_model::llm::ModelId;
use oneiron_model::llm::ModelLocality;
use oneiron_run_budget::run_budget::BudgetLine;
use oneiron_run_budget::run_budget::LeaseUnit;
pub use oneiron_verb_wire::skill_optimize::training_choice::SwapChoice;
pub use oneiron_verb_wire::training_pack::types::ArtifactPin;
pub use oneiron_verb_wire::training_pack::types::CalibrationResult;
pub use oneiron_verb_wire::training_pack::types::CandleParityCheck;
pub use oneiron_verb_wire::training_pack::types::CheckpointFileKind;
pub use oneiron_verb_wire::training_pack::types::ExportCheck;
pub use oneiron_verb_wire::training_pack::types::QuestionExportCheck;
pub use oneiron_verb_wire::training_pack::types::TrainingOwner;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeCase {
    pub id: String,
    pub input: Value,
}

/// Host measurements on one fixed input, comparing training and export weights.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeMeasurement {
    pub probe_id: String,
    pub input_blake3: [u8; 32],
    /// The trainer's BLAKE3 of the probe's token ids, as the windows it fed
    /// the encoder (FIX 7568); none from a trainer that reports none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens_blake3: Option<[u8; 32]>,
    pub training_argmax: u64,
    pub export_argmax: u64,
    pub max_logit_difference: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitPolicy {
    /// OF-578 assigns source families before derivation and seals this cohort.
    pub held_out_cohort: EntityId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitSide {
    Training,
    HeldOut,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitRow {
    pub receipt: String,
    pub family: EntityId,
    pub content_blake3: [u8; 32],
    pub side: SplitSide,
}

/// Where a question run's rows come from: the source-family split and the
/// consent behind them, as the ingress receipted them. The trainer echoes
/// both and certifies neither.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectorProvenance {
    pub split_receipt: String,
    pub consent_receipt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputePin {
    pub choice: ComputeChoice,
    pub connector: String,
    pub adapter: String,
    pub origin: String,
    pub locality: ModelLocality,
    pub payer: Payer,
    pub binding_blake3: [u8; 32],
    pub quantity: u64,
    pub unit_cost: u64,
    pub cost_unit: LeaseUnit,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrainingDispatch {
    pub declaration_revision: u32,
    pub budget: BudgetLine,
    pub permit: Value,
    pub dispatched: bool,
    /// The completion that first recorded a result claimed the run's one
    /// Used settlement; a later idempotent completion settles nothing.
    pub settlement_claimed: bool,
}

/// The teachers a run declaration names, as the owner authorized them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrainingTeachersPin {
    pub models: Vec<ModelId>,
    pub aliases: BTreeMap<String, ModelId>,
    pub target: String,
    pub purpose: String,
}

/// Why the host cannot advance an authorized or returned run yet, for the
/// owner to read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrainingHold {
    pub code: String,
    pub detail: String,
    pub at: u64,
}
