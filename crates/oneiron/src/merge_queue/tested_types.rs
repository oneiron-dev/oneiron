//! Core half of `merge_queue::tested_types`: its store-layer items live in `oneiron_store::merge_queue::tested_types` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::merge_queue::tested_types::*;

use super::CheckPhase;
use crate::EntityId;
use crate::store::code_revision_record::CodeRevision;
use crate::store::repo_fork::RepoForkHash;
use serde::{Deserialize, Serialize};

/// One bound checker receipt a tested revision stands on. The receipt on
/// the checker's work row keeps the inputs, action, output and attempt; the
/// link names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueReceiptLink {
    pub phase: CheckPhase,
    /// The checked path's mask; zero for the baseline.
    pub mask: u64,
    /// The checker work row that holds the receipt.
    pub work_ref: String,
    pub inputs_digest: String,
    /// The verdict the receipt bound; the baseline records none.
    pub verdict_ref: Option<String>,
}

/// The immutable queue record of one tested complete tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueTestedRevision {
    pub schema_version: u8,
    /// The CODE_ARTIFACT the queue serves.
    pub repo: EntityId,
    /// The proven object store's hex identity.
    pub store: String,
    /// The checked-init work key the queue's tested chain descends from.
    pub init_work: String,
    pub baseline_commit: String,
    pub baseline_tree: String,
    /// The contract baseline the verdicts compare to.
    pub oracle_baseline: String,
    pub plan_digest: String,
    /// The exact checked commit and tree.
    pub commit: String,
    pub tree: String,
    pub target: QueueTestedTarget,
    /// Every fast check that earned landing, by mask.
    pub fast: Vec<QueueReceiptLink>,
    /// The slow check of the landed tree.
    pub slow: QueueReceiptLink,
    /// The digest of the complete document and blob inventory.
    pub inventory_digest: [u8; 32],
    /// Each accepted push this tree consumed completely, sorted (G4 PR2):
    /// its checked root is the push's incoming tip. Empty on every other
    /// revision, which encodes as before.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub received_pushes: Vec<CodePushSourceLink>,
}

/// The current green's sealed revision, issued by the queue after it read
/// the persisted record, its folds and evidence and matched them to the
/// live green pointer. A read capability: it grants no write, review or
/// publication authority. No caller constructs or decodes one.
pub struct GreenQueueRevision {
    pub(super) revision: CodeRevision,
    pub(super) store: String,
    pub(super) commit: String,
}

impl GreenQueueRevision {
    #[must_use]
    pub fn revision_id(&self) -> EntityId {
        self.revision.revision_id
    }

    #[must_use]
    pub fn revision(&self) -> &CodeRevision {
        &self.revision
    }

    #[must_use]
    pub fn store(&self) -> &str {
        &self.store
    }

    #[must_use]
    pub fn commit(&self) -> &str {
        &self.commit
    }
}

/// A finalized revision the queue issued from a validated target: the
/// record, the source row its link attaches to and the stored repository
/// pointer. Only the queue builds one.
pub(crate) struct QueueRevisionSeal {
    pub(super) revision: CodeRevision,
    pub(super) source: QueueSealSource,
    pub(super) repo_ref: String,
}

impl QueueRevisionSeal {
    pub(crate) fn revision(&self) -> &CodeRevision {
        &self.revision
    }

    /// The queue's stored local folder pointer, canonical.
    pub(crate) fn repo_ref(&self) -> &str {
        &self.repo_ref
    }
}
