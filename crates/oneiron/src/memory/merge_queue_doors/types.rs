use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::contract_oracle::{AffectedTests, ContractVerdict};
use crate::merge_queue::{BatchState, Quarantine, QueueDriveView, QueueGreenExportView};

/// One merge queue, named by its repository.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MergeQueueRepoRequest {
    /// An existing CODE_ARTIFACT whose stored pointer is a local folder,
    /// never a path or a remote pointer.
    pub repo: EntityId,
}

/// One batch of one merge queue.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MergeQueueBatchRequest {
    /// An existing CODE_ARTIFACT whose stored pointer is a local folder.
    pub repo: EntityId,
    /// The batch digest an enqueue or a requeue returned, 64 hex characters.
    pub batch_ref: String,
}

/// Stored repository proposals to queue as one batch. The proposals carry
/// their own bytes and reviews; this request carries neither.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MergeQueueEnqueueRequest {
    /// An existing CODE_ARTIFACT whose stored pointer is a local folder.
    pub repo: EntityId,
    /// Stored repository proposals, in batch order. One call is one batch.
    pub proposals: Vec<EntityId>,
    /// The queue green Git commit the caller observed, 40 hex characters.
    /// Each proposal must be pinned at it.
    pub base_green: String,
}

/// Named batches of one merge queue to read.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MergeQueueObserveRequest {
    /// An existing CODE_ARTIFACT whose stored pointer is a local folder.
    pub repo: EntityId,
    /// Batch digests to read, in this order. Empty reads the pointers only;
    /// no batch is found for the caller by scan.
    pub batches: Vec<String>,
}

/// One speculative subset of a staged batch. Its worktree stays on the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeQueuePathView {
    /// The bitset of included proposals, by batch order.
    pub mask: u64,
    /// The speculative Git commit.
    pub commit: String,
    /// The speculative Git tree.
    pub tree: String,
    /// The stored contract verdict of its fast check, once checked.
    pub verdict_ref: Option<String>,
}

/// One merge batch as the queue holds it, without proposal bytes or host
/// paths. The state is the queue's own.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeQueueBatchView {
    pub batch_ref: String,
    /// The contract baseline the batch is checked against.
    pub baseline_ref: String,
    /// The queue head Git commit the batch was formed on.
    pub expected_head: String,
    /// The queue green Git commit the batch was formed on.
    pub base_green: String,
    /// The proposal ids, in batch order.
    pub proposals: Vec<String>,
    pub state: BatchState,
    pub paths: Vec<MergeQueuePathView>,
    /// The Git commit the batch landed as, once landed.
    pub landed_head: Option<String>,
    /// The stored contract verdict of its slow check, once checked.
    pub slow_verdict_ref: Option<String>,
    /// The minimal failing group a red diagnosis kept.
    pub quarantine: Option<Quarantine>,
    pub selected_tests: AffectedTests,
}

/// The queue pointers: raw Git commits, not tested-tree records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeQueuePointersView {
    pub repo: EntityId,
    /// The fast-tested head Git commit.
    pub head_commit: String,
    /// The slow-tested green Git commit.
    pub green_commit: String,
    /// Landed batches whose slow check has not settled, in landing order.
    pub pending_slow_batch_refs: Vec<String>,
}

/// The answer of one survivor requeue. It names the source batch for this
/// answer only; the queue keeps no durable parent or child link.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeQueueRequeueView {
    pub source_batch_ref: String,
    /// The new batch of survivors; `None` when none survived.
    pub batch: Option<MergeQueueBatchView>,
}

/// The pointers, the named batches in request order and the stored contract
/// verdicts those batches name, each once, in first-named order. A verdict is
/// not a check execution receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeQueueObservation {
    pub repo: EntityId,
    pub head_commit: String,
    pub green_commit: String,
    pub pending_slow_batch_refs: Vec<String>,
    pub batches: Vec<MergeQueueBatchView>,
    pub verdicts: Vec<ContractVerdict>,
    /// The automatic driver's view of each named batch, in request order:
    /// its status or typed hold, the checker work and receipts that bind
    /// it and its overlap handoff (FIX 6868). An unenrolled queue answers
    /// `unenrolled`.
    pub drive: Vec<QueueDriveView>,
    /// The current green's tested revision and whether `export_green`
    /// holds, with its named reason and way out (G2 PR3, CALLS D and E).
    pub green_export: QueueGreenExportView,
}
