//! Moved from `crates/oneiron/src/memory/merge_queue_doors/types.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

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
