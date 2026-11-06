//! The drafter's records (FIX 12569): its versions, the binding of each
//! target, its events and the owner's policy. Ids, digests, states, counts
//! and times only: never conversation text, tokens, weights or keys.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::training_pack::SourcePin;

/// What a drafter drafts for and loads into: the target model, the
/// tokenizer both share and the serving runtime family the artifact loads
/// in. Two targets with the same pins share one binding.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct DrafterTarget {
    /// The target model's identity, as its serving worker reports it.
    pub model: String,
    /// The tokenizer identity the drafter and the target share.
    pub tokenizer: String,
    /// The serving runtime family and artifact format the drafter loads in.
    pub runtime: String,
}

impl DrafterTarget {
    /// The binding key: BLAKE3 of the canonical JSON of the three pins.
    ///
    /// # Errors
    /// The pins do not encode.
    pub(crate) fn key(&self) -> crate::Result<[u8; 32]> {
        super::hash_json(self)
    }
}

/// What a binding serves, or what a version continued from.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DrafterServing {
    /// The stock drafter the deployment ships.
    Stock,
    /// One retained version of this vault's own.
    Version(EntityId),
}

impl DrafterServing {
    /// The version this names, `None` for stock.
    #[must_use]
    pub fn version(self) -> Option<EntityId> {
        match self {
            Self::Stock => None,
            Self::Version(version) => Some(version),
        }
    }
}

/// The recipe a nightly retrain runs, as data: the engine supplies no
/// learning rate, epoch count or other number of its own (FIX 14974).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterRecipe {
    /// The trainer family's name, as a host's trainer connector lists it
    /// (`[models.training.drafters.<name>].recipes`).
    pub id: String,
    /// The immutable source revision of the trainer and the recipe.
    pub revision: SourcePin,
    /// The recipe's settings, read by its trainer only.
    pub settings: serde_json::Value,
    /// The GPU wall seconds one night's training may take: the quantity its
    /// run admission reserves at the connector's unit cost, and the time
    /// after which the host stops the trainer.
    pub gpu_seconds: u64,
    /// The GPU memory, in MiB, the trainer declares on its device's work
    /// line beside the serving worker.
    pub device_memory_mib: u64,
}

/// Everything a version's training read, each named by its id, so an erase
/// of any of them reaches the version: its own corpus and, for a version
/// continued from another, that version's set too.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterDependencies {
    /// The records whose bytes the corpus holds.
    pub sources: Vec<EntityId>,
    /// The worlds those records sit in, quoted and derived context included.
    pub worlds: Vec<EntityId>,
    /// The actors who wrote them.
    pub authors: Vec<EntityId>,
    /// Anyone else whose erase the corpus must follow.
    pub erase_subjects: Vec<EntityId>,
    /// The quoted replies, tool results and fold summaries it holds, and
    /// what they in turn were derived from.
    pub derived: Vec<EntityId>,
    /// Whether the lists are known whole. A version whose set is not goes on
    /// any erase.
    pub precise: bool,
}

impl DrafterDependencies {
    /// Whether the set names `id` in any list.
    pub(crate) fn names(&self, id: &EntityId) -> bool {
        [
            &self.sources,
            &self.worlds,
            &self.authors,
            &self.erase_subjects,
            &self.derived,
        ]
        .iter()
        .any(|list| list.contains(id))
    }

    /// Whether the set names a world of `worlds`.
    pub(crate) fn names_world_of(&self, worlds: &BTreeSet<EntityId>) -> bool {
        self.worlds.iter().any(|world| worlds.contains(world))
    }
}

/// Where one version stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DrafterVersionState {
    /// Its corpus is pinned and its job queued; nothing trained yet.
    Prepared,
    /// Dispatched to the trainer.
    Training,
    /// Trained, its sealed artifact published; not yet qualified.
    Returned,
    /// Qualified on held-out turns and retained: it may serve, and it may be
    /// reverted to.
    Qualified,
    /// Failed training or qualification; kept as evidence, never served.
    Rejected,
    /// A source its ancestry names was erased: its key is retired, it never
    /// serves and it is never reverted to.
    Erased,
}

/// One file of a sealed artifact, as the host verified it before sealing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterArtifactFile {
    /// The file's name inside the load set.
    pub name: String,
    /// Its plaintext length.
    pub bytes: u64,
    /// Its plaintext BLAKE3.
    pub blake3: [u8; 32],
    /// The sealed file's length.
    pub sealed_bytes: u64,
}

/// One version's sealed load set: a reference to bytes sealed under the
/// version's own erasable key. It names the key by its random ref only and
/// never holds key bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterArtifact {
    /// Its random id, never derived from its bytes: the sealed load set's
    /// name and its key's incarnation.
    pub id: [u8; 16],
    /// The erasable key's random ref: its name in custody, never the key.
    pub key_ref: [u8; 32],
    /// Each file of the load set.
    pub files: Vec<DrafterArtifactFile>,
    /// BLAKE3 of the canonical JSON of `files`: the load set's digest a
    /// serving binding verifies.
    pub load_set_blake3: [u8; 32],
}

/// One sealed side of a version's corpus (FIX 14973): its training examples
/// or its held-out examples, one JSON line each, sealed chunk by chunk under
/// an erasable key of its own. The record names the key by its random ref
/// only, and pins the plaintext by its length and BLAKE3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterCorpusFile {
    /// Its random id, never derived from its bytes: the sealed file's name
    /// and its key's incarnation.
    pub id: [u8; 16],
    /// The erasable key's random ref: its name in custody, never the key.
    pub key_ref: [u8; 32],
    /// How many examples it holds.
    pub examples: u64,
    /// How many source families those examples come from.
    pub families: u64,
    /// Its plaintext length.
    pub bytes: u64,
    /// Its plaintext BLAKE3.
    pub blake3: [u8; 32],
    /// How many sealed chunks it is written in.
    pub chunks: u64,
}

/// What one version's corpus holds (FIX 14973): its form, its two sealed
/// sides, the pin of its split and how many replies the export left out,
/// by reason. Counts and digests only, never an example.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterCorpus {
    /// The form every example takes, as its trainer reads it.
    pub form: String,
    /// The examples the trainer receives.
    pub training: DrafterCorpusFile,
    /// The examples only the evaluator opens; never sent to the trainer.
    pub held_out: DrafterCorpusFile,
    /// BLAKE3 of the canonical JSON of the held-out families, sorted: the
    /// split's pin.
    pub held_out_families_blake3: [u8; 32],
    /// The replies the export left out, by reason code.
    pub omitted: BTreeMap<String, u64>,
}

/// One drafter version, immutable in what it is, and its run: the record of
/// one attempted or trained head. No second training ledger holds the same
/// attempt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterVersion {
    pub id: EntityId,
    pub target: DrafterTarget,
    /// What it continued from: stock, or the last kept version.
    pub parent: DrafterServing,
    pub recipe: DrafterRecipe,
    /// The policy revision its night pinned.
    pub policy_revision: u64,
    /// The vault's recorded clock its corpus was cut at: nothing recorded
    /// later trains it.
    pub cutoff: u64,
    /// Its own corpus's dependency set. The parent's is read through
    /// `parent`, so an erase follows the whole ancestry.
    pub dependencies: DrafterDependencies,
    /// The Coach job that trains it, a reference only.
    pub job: Option<AttemptId>,
    /// The BLAKE3 of its pinned training spec, once the host prepared one.
    pub spec_blake3: Option<[u8; 32]>,
    pub state: DrafterVersionState,
    /// Bumps on every state change: a completion names the generation it
    /// was dispatched at, and a moved one is refused.
    pub generation: u64,
    /// Its sealed load set, once published; `None` once erased.
    pub artifact: Option<DrafterArtifact>,
    /// Its sealed corpus, pinned when the night prepared it; `None` once
    /// erased.
    pub corpus: Option<DrafterCorpus>,
    /// Its qualification record, once the host evaluated it.
    pub evaluation: Option<EntityId>,
    /// Its training job, once the host dispatched it (FIX 14974).
    pub training: Option<DrafterTraining>,
    /// The vault's recorded clock when it was prepared and last changed.
    pub created_at: u64,
    pub updated_at: u64,
}

/// One version's training job, as the host dispatched it and as it ended
/// (FIX 14974): the connector and quote it ran under and the receipt's
/// measurements. Names, counts and digests only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterTraining {
    /// The trainer connector it was dispatched on, by its configured name.
    pub connector: String,
    /// The connector's immutable revision at dispatch.
    pub connector_revision: Option<String>,
    /// The GPU wall seconds its quote reserved, the unit cost and the unit.
    pub quoted_units: u64,
    pub unit_cost: u64,
    pub cost_unit: String,
    /// The version's generation the dispatch moved it to: its completion
    /// names it, and a moved one is refused.
    pub generation: u64,
    /// The vault's recorded clock at dispatch.
    pub dispatched_at: u64,
    /// The GPU wall seconds the trainer measured, as its receipt reports.
    pub gpu_seconds: Option<u64>,
    /// BLAKE3 of the trainer's receipt, once one was read.
    pub receipt_blake3: Option<[u8; 32]>,
    /// The vault's recorded clock when the job ended.
    pub finished_at: Option<u64>,
    /// Why the job ended without a trained version; `None` while it runs
    /// and once it trained.
    pub failure: Option<DrafterTrainingFailure>,
}

/// Why a dispatched training ended without a trained version (FIX 14974).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DrafterTrainingFailure {
    /// The host refused the job before the trainer started: its device line
    /// stopped, its job directory or its inputs did not stage, or the
    /// process did not start.
    Refused,
    /// The trainer ended with no receipt, or a receipt that says it did not
    /// train.
    TrainerFailed,
    /// The receipt or an output file did not verify against the job.
    ReceiptUnverified,
    /// The trained load set did not seal or publish.
    SealFailed,
    /// The trainer ran past the recipe's GPU seconds and was stopped.
    OverBudget,
    /// The trainer's process is gone with no receipt: a restart lost it.
    Lost,
    /// The policy went off, or its recipe changed, while it trained; the
    /// trainer was stopped.
    Cancelled,
    /// A source its ancestry names was erased while it trained.
    Erased,
}

/// One target's active drafter pointer. A target with no row serves stock
/// at generation 0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterBinding {
    pub target: DrafterTarget,
    /// What serves now.
    pub serving: DrafterServing,
    /// Bumps on every change: a revert or an activation names the
    /// generation it read, and a moved one is refused.
    pub generation: u64,
    /// What served before the last change; stock where that was erased.
    pub previous: DrafterServing,
    /// The event that made the last change; `None` for a target never bound.
    pub changed_by: Option<EntityId>,
    /// The vault's recorded clock at the last change.
    pub changed_at: u64,
}

impl DrafterBinding {
    /// A target never bound: stock at generation 0.
    pub(crate) fn stock(target: DrafterTarget) -> Self {
        Self {
            target,
            serving: DrafterServing::Stock,
            generation: 0,
            previous: DrafterServing::Stock,
            changed_by: None,
            changed_at: 0,
        }
    }
}

/// Who made a drafter event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DrafterActor {
    /// The vault's owner.
    Owner(EntityId),
    /// An agent under its live Grant naming the act.
    Agent(EntityId),
    /// The Coach, on the nightly runner.
    Coach,
    /// The host that serves the vault's bindings on its own worker.
    Host,
    /// A source erase.
    Erase,
    /// An actor since erased.
    Erased,
}

impl DrafterActor {
    /// Forgets `id` when this names it; whether it did.
    pub(crate) fn forget(&mut self, id: &EntityId) -> bool {
        let named = matches!(*self, Self::Owner(actor) | Self::Agent(actor) if actor == *id);
        if named {
            *self = Self::Erased;
        }
        named
    }
}

/// One change of a binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterBindingChange {
    pub target: DrafterTarget,
    pub from: DrafterServing,
    pub to: DrafterServing,
    /// The binding's generation after the change.
    pub generation: u64,
}

/// Why a night did not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DrafterSkipReason {
    /// The owner's policy is off.
    PolicyOff,
}

/// Why a night held: nothing trained, and serving did not change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DrafterHoldReason {
    /// No recipe is chosen, or no trainer connector on this host lists the
    /// recipe's trainer family.
    NoTrainerRecipe,
    /// This host serves no drafter target: no managed worker it launches
    /// serves a draft.
    NoDrafterTarget,
    /// The policy moved while the corpus was exported.
    PolicyMoved,
    /// The corpus had no training example or no held-out example.
    EmptyCorpus,
    /// The prepared corpus's sealed training side did not open.
    CorpusMissing,
    /// An earlier night's version of the same target still trains.
    TrainingInProgress,
    /// The recipe's quote built no run admission, or the budget refused it.
    NoAdmission,
}

/// How one night's retrain ended. Only `trained` is a retrain, and it names
/// the version that trained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DrafterRetrainOutcome {
    Skipped {
        reason: DrafterSkipReason,
    },
    Held {
        reason: DrafterHoldReason,
    },
    /// The night trained `version`: its sealed load set is published and it
    /// waits for its qualification.
    Trained {
        version: EntityId,
    },
    /// The night dispatched `version` and its training ended without a
    /// trained head.
    Failed {
        version: EntityId,
        reason: DrafterTrainingFailure,
    },
}

/// Why a version was rolled back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DrafterRollbackReason {
    /// Serving measured slower than the head it replaced.
    Slowdown,
    /// Its output was not token-identical to the target's.
    OutputMismatch,
    /// The worker failed to load or serve it.
    WorkerError,
}

/// What a drafter event records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DrafterEventKind {
    /// One night's retrain: what its prepare step pinned and how it ended.
    Retrain {
        attempt: AttemptId,
        policy_revision: u64,
        cutoff: u64,
        outcome: DrafterRetrainOutcome,
    },
    /// A version's held-out qualification.
    Qualify {
        version: EntityId,
        passed: bool,
        evaluation: Option<EntityId>,
    },
    /// A qualified version went into service.
    Activate { version: EntityId },
    /// A serving version was rolled back.
    Rollback {
        version: EntityId,
        reason: DrafterRollbackReason,
    },
    /// The owner or an agent reverted a target to a retained version.
    Revert { version: EntityId },
    /// A source erase: the versions it reached, now erased, and the jobs
    /// of theirs it fenced.
    Erase {
        versions: Vec<EntityId>,
        jobs: Vec<AttemptId>,
    },
    /// The owner's policy at a new revision.
    Policy { revision: u64 },
    /// A new worker incarnation proved it serves `target`'s binding at
    /// `generation`: stock, or a version, with the draft identity its
    /// answers name (`draft_weights_digest`).
    Served {
        target: DrafterTarget,
        serving: DrafterServing,
        generation: u64,
        draft_digest: Option<String>,
    },
}

/// One content-free drafter event, kept for the owner's history and the
/// morning report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterEvent {
    /// Time-ordered: the events table reads in the order they happened.
    pub id: EntityId,
    /// The vault's recorded clock.
    pub at: u64,
    pub by: DrafterActor,
    pub kind: DrafterEventKind,
    /// The binding change it made, if any.
    pub change: Option<DrafterBindingChange>,
}
