//! Pins and receipts shared by the training pack and its host adapters.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::entity_id::EntityId;
use crate::llm::manifest::{ModelBinding, ModelRole};
use crate::llm::run_admission::{BudgetLine, LeaseUnit, Payer};
use crate::llm::{ModelId, ModelLocality};
use crate::receipt::ERASED_CALL_IDENTITY;
use crate::skill_optimize::{EvalCohort, EvalExposure, EvalSeat};

use super::TrainingTarget;

/// A source is a repository and an immutable revision, never a moving branch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SourcePin {
    pub repository: String,
    pub revision: String,
}

/// A particular version in the vault's existing blob custody.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArtifactPin {
    pub artifact: EntityId,
    pub version: u64,
    pub blake3: [u8; 32],
    pub bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointFileKind {
    Weights,
    Tokenizer,
    Config,
    Template,
    AdapterConfig,
}

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

/// There is no default destination. External explicitly approves this run's egress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComputeChoice {
    OwnerMachines,
    External,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrainingState {
    Prepared,
    /// The owner authorized this exact spec; the host dispatches it once.
    Authorized,
    Running,
    ConnectorFailed,
    Returned,
    Scored,
    Bound,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrainingDispatch {
    pub declaration_revision: u32,
    pub budget: BudgetLine,
    pub permit: Value,
    pub dispatched: bool,
}

/// The teachers a run declaration names, as the owner authorized them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrainingTeachersPin {
    pub models: Vec<ModelId>,
    pub target: String,
    pub purpose: String,
}

/// The facts of a declared run the dispatch checks, frozen when the owner
/// authorizes; a changed declaration refuses the dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrainingDeclarationPin {
    pub teachers: Option<TrainingTeachersPin>,
    pub budget: BudgetLine,
}

/// Where an authorization came from: the owner's own door, or their yes on
/// a training offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TrainingAuthorizationSource {
    Direct,
    Offer {
        offer: EntityId,
        offer_digest: String,
    },
}

/// The owner a run, an authorization or a swap receipt names: an actor, or
/// no one once that actor was erased (FIX 3520). It reads and writes as the
/// actor's hex id, or as [`ERASED_CALL_IDENTITY`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrainingOwner {
    Actor(EntityId),
    Erased,
}

impl TrainingOwner {
    /// Whether this is `actor`.
    #[must_use]
    pub fn is(self, actor: EntityId) -> bool {
        self == Self::Actor(actor)
    }

    /// Makes this no one when it is `actor`; whether it was.
    pub(crate) fn forget(&mut self, actor: EntityId) -> bool {
        let named = self.is(actor);
        if named {
            *self = Self::Erased;
        }
        named
    }
}

impl Serialize for TrainingOwner {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Actor(id) => serializer.serialize_str(&id.to_hex()),
            Self::Erased => serializer.serialize_str(ERASED_CALL_IDENTITY),
        }
    }
}

impl<'de> Deserialize<'de> for TrainingOwner {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value == ERASED_CALL_IDENTITY {
            return Ok(Self::Erased);
        }
        EntityId::from_hex(&value)
            .map(Self::Actor)
            .map_err(serde::de::Error::custom)
    }
}

/// Its schema is its wire form: the actor's hex id, or [`ERASED_CALL_IDENTITY`].
impl schemars::JsonSchema for TrainingOwner {
    fn schema_name() -> String {
        "TrainingOwner".to_owned()
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        <String as schemars::JsonSchema>::json_schema(generator)
    }
}

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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ExportCheck {
    pub hash_mismatches: Vec<String>,
    pub probe_coverage_matches: bool,
    pub probe_checkpoints_match: bool,
    pub settings_match: bool,
    pub harness_matches: bool,
    pub argmax_flips: u64,
    pub max_logit_difference: f64,
    pub tolerance: f64,
    /// A question head's own producer check; a role run has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub question_check: Option<QuestionExportCheck>,
    /// The host's Candle-side reproduction of a question head's probe
    /// evidence (FIX 7568); a role run has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candle_parity: Option<CandleParityCheck>,
}

/// What the host reproduced of a trained classifier's receipt on the stack
/// that would serve it (FIX 7568), before it may serve: a check of our own
/// artifact against the trainer's word.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CandleParityCheck {
    /// Every probe's token ids, rendered and tokenized here with the
    /// export's own pinned tokenizer and cut into its windows, hash to the
    /// trainer's.
    pub tokens_match: bool,
    /// The probes whose ids did not reproduce, by id.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub token_mismatches: Vec<String>,
    /// Whether the export's logits reproduced in Candle: `None` while no
    /// Candle classifier loader is built here, so none was run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logits_match: Option<bool>,
}

impl CandleParityCheck {
    /// No half that ran failed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.tokens_match && self.logits_match != Some(false)
    }
}

/// What a question head's trainer also measured on its fixed probes: every
/// logit finite, the export's tokens the training's, and its own verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct QuestionExportCheck {
    pub finite: bool,
    pub tokens_match: bool,
    pub passed: bool,
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
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CalibrationResult {
    pub temperature: f64,
    pub brier_score: f64,
    pub calibration_error: f64,
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

/// A separate owner decision; an override keeps the failed checks on its receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SwapChoice {
    Evaluated,
    ExplicitOverride { reason: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RoleSwapReceipt {
    pub id: EntityId,
    pub run: EntityId,
    pub owner: TrainingOwner,
    pub at: u64,
    pub role: ModelRole,
    pub previous: Option<ModelBinding>,
    pub binding: ModelBinding,
    pub checkpoint: PinnedCheckpoint,
    pub evaluation: Option<HeldOutResult>,
    pub checks: ExportCheck,
    pub exact_hash_overlaps: u64,
    pub promotion_exposure: Option<EvalExposure>,
    pub choice: SwapChoice,
}
