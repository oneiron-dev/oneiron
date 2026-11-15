//! Moved from `crates/oneiron/src/merge_queue/tested_types.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::merge_queue::types::CheckPhase;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_store::merge_queue::tested_types::*;
use serde::Deserialize;
use serde::Serialize;

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
