//! Pins and receipts shared by the training pack and its host adapters.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::entity_id::EntityId;
use crate::llm::manifest::{ModelBinding, ModelRole};
use crate::llm::run_admission::{BudgetLine, LeaseUnit, Payer};
use crate::llm::{ModelId, ModelLocality};
use crate::skill_optimize::{EvalCohort, EvalExposure, EvalSeat};

use super::{DataTimeline, TrainingTarget};

/// A source is a repository and an immutable revision, never a moving branch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SourcePin {
    pub repository: String,
    pub revision: String,
}

#[doc(hidden)]
pub use oneiron_verb_wire::training_pack::types::{
    ArtifactPin, CalibrationResult, CandleParityCheck, CheckpointFileKind, ExportCheck,
    QuestionExportCheck, TrainingOwner,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CheckpointFilePin {
    pub name: String,
    pub kind: CheckpointFileKind,
    pub source: SourcePin,
    pub content: ArtifactPin,
    /// The producer's hash, kept even when it differs from the bytes received.
    pub declared_blake3: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PinnedCheckpoint {
    pub model: ModelId,
    pub files: Vec<CheckpointFilePin>,
}

/// Bytes handed back by a connector, or imported by the owner.
#[derive(Debug)]
pub struct CheckpointFileUpload {
    pub name: String,
    pub kind: CheckpointFileKind,
    pub source: SourcePin,
    pub blake3: [u8; 32],
    pub bytes: Vec<u8>,
}

#[derive(Debug)]
pub struct CheckpointUpload {
    pub model: ModelId,
    pub files: Vec<CheckpointFileUpload>,
}

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

/// The skill supplies the recipe; the engine supplies no model or tolerance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrainingPlan {
    /// A role and its binding, or one detector question (FIX 7263).
    #[serde(flatten)]
    pub target: TrainingTarget,
    pub seat: EvalSeat,
    pub starting_checkpoint: PinnedCheckpoint,
    pub purpose: String,
    pub settings: Value,
    pub harness: SourcePin,
    pub probes: Vec<ProbeCase>,
    pub export_logit_tolerance: f64,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusSplit {
    pub export_receipt: EntityId,
    pub export: ArtifactPin,
    pub training: ArtifactPin,
    pub held_out: ArtifactPin,
    pub cohort: EvalCohort,
    pub rows: Vec<SplitRow>,
    pub exact_hash_overlaps: u64,
    /// The sources with other people the owner ticked "I obtained consent"
    /// for this run (ARCH-0053 #training-inputs), sorted; such a source not
    /// here stayed out of the corpus.
    pub consented_sources: Vec<EntityId>,
    /// The pairs the export left out before the split, by reason code.
    pub excluded: BTreeMap<String, u64>,
    /// A question run's split and consent receipts, from its detector-row
    /// ingress; a role run's reservoir corpus has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detector: Option<DetectorProvenance>,
}

/// Where a question run's rows come from: the source-family split and the
/// consent behind them, as the ingress receipted them. The trainer echoes
/// both and certifies neither.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectorProvenance {
    pub split_receipt: String,
    pub consent_receipt: String,
}

pub use crate::skill_optimize::training_choice::ComputeChoice;

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

pub use crate::skill_optimize::training_choice::TrainingState;

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

/// The facts of a declared run the dispatch checks, frozen when the owner
/// authorizes; a changed declaration refuses the dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrainingDeclarationPin {
    pub teachers: Option<TrainingTeachersPin>,
    pub budget: BudgetLine,
    pub connectors: BTreeSet<String>,
    pub custody_overrides: BTreeSet<String>,
}

pub use crate::skill_optimize::training_choice::TrainingAuthorizationSource;

/// The owner's yes on one prepared spec and declaration. It holds no
/// credential, key, lease or permit; the host takes a fresh permit at dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrainingAuthorization {
    pub owner: TrainingOwner,
    pub at: u64,
    pub spec_blake3: [u8; 32],
    pub declaration: TrainingDeclarationPin,
    pub source: TrainingAuthorizationSource,
}

/// Why the host cannot advance an authorized or returned run yet, for the
/// owner to read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrainingHold {
    pub code: String,
    pub detail: String,
    pub at: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrainingResult {
    pub training_checkpoint: PinnedCheckpoint,
    pub exported_checkpoint: PinnedCheckpoint,
    pub probes: Vec<ProbeMeasurement>,
    pub checks: ExportCheck,
    pub connector_receipt: Value,
    pub settings: Value,
    pub harness: SourcePin,
    /// Taken from the run admission, not the connector's own report.
    pub teachers: Value,
    pub service_units: u64,
    /// Where the run changed its data mixture or restarted from an earlier
    /// checkpoint (ARCH-0053 #training-timeline), as the trainer's receipt
    /// reported it; none from a run that did neither.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeline: Option<DataTimeline>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HeldOutResult {
    pub exposure: EntityId,
    pub checkpoint_blake3: [u8; 32],
    pub held_out_blake3: [u8; 32],
    pub harness: SourcePin,
    pub cases: u64,
    pub metrics: BTreeMap<String, f64>,
    pub calibration: Option<CalibrationResult>,
    pub verifier_logs: Vec<ArtifactPin>,
    /// The evaluator's task-specific verdict. No generic score floor is invented here.
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrainingRun {
    pub id: EntityId,
    pub owner: TrainingOwner,
    pub created_at: u64,
    pub plan: TrainingPlan,
    pub compute: ComputePin,
    pub corpus: CorpusSplit,
    pub spec_blake3: [u8; 32],
    pub state: TrainingState,
    pub dispatch: Option<TrainingDispatch>,
    pub result: Option<TrainingResult>,
    pub evaluation: Option<HeldOutResult>,
    pub eval_exposure: Option<EvalExposure>,
    pub authorization: Option<TrainingAuthorization>,
    /// Read while the run waits on the host; dispatch clears it.
    pub hold: Option<TrainingHold>,
    /// The rows the run was prepared, trained and scored from (FIX 5760):
    /// its corpus pairs with their skills and TURNs, its pinned checkpoint
    /// files, its cohort's cases and labels, the files its connector handed
    /// back and its verifier logs. `None`, unknown, once any of them is. The
    /// run's id and its artifact strings are not among them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_rows: Option<Vec<EntityId>>,
}

/// The owner picks the recipe, a sealed source-family cohort and compute per run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrainingPackDraft {
    pub plan: TrainingPlan,
    pub split: SplitPolicy,
    pub compute: ComputeChoice,
    pub quantity: u64,
    /// The sources with other people the owner selects for this run, each
    /// ticked "I obtained consent". The owner's own sources need no tick.
    #[serde(default)]
    pub consented_sources: Vec<EntityId>,
}

pub use crate::skill_optimize::training_choice::SwapChoice;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RoleSwapReceipt {
    pub id: EntityId,
    pub run: EntityId,
    pub owner: TrainingOwner,
    pub at: u64,
    pub role: ModelRole,
    pub previous: Option<ModelBinding>,
    /// The actual ROLES receipt replaced at bind time, not a history search.
    pub previous_swap: Option<EntityId>,
    pub binding: ModelBinding,
    pub checkpoint: PinnedCheckpoint,
    pub evaluation: Option<HeldOutResult>,
    pub checks: ExportCheck,
    pub exact_hash_overlaps: u64,
    pub promotion_exposure: Option<EvalExposure>,
    pub choice: SwapChoice,
}
