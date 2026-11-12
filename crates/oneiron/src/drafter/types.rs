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

#[doc(hidden)]
pub use oneiron_verb_wire::drafter::types::{
    DrafterActor, DrafterArtifact, DrafterArtifactFile, DrafterCorpus, DrafterCorpusFile,
    DrafterDependencies, DrafterHoldReason, DrafterRetrainOutcome, DrafterRollbackReason,
    DrafterServing, DrafterSkipReason, DrafterTraining, DrafterTrainingFailure,
    DrafterVersionState,
};

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
