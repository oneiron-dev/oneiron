//! Moved from `crates/oneiron/src/drafter/types.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::attempt_id::AttemptId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

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
    pub fn names(&self, id: &EntityId) -> bool {
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
    pub fn names_world_of(&self, worlds: &BTreeSet<EntityId>) -> bool {
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
    pub fn forget(&mut self, id: &EntityId) -> bool {
        let named = matches!(*self, Self::Owner(actor) | Self::Agent(actor) if actor == *id);
        if named {
            *self = Self::Erased;
        }
        named
    }
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
