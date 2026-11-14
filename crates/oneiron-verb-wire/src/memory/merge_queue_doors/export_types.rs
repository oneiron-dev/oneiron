//! Moved from `crates/oneiron/src/memory/merge_queue_doors/export_types.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// Export one queue's current tested green through the reviewed origin
/// export.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MergeQueueGreenExportRequest {
    /// An existing CODE_ARTIFACT whose checked queue tested the green.
    pub repo: EntityId,
    /// The served repository the export publishes to; its object store
    /// must be the queue's.
    pub served_repo: String,
    /// The owner's live checkout id, 32 lower-hex characters.
    pub checkout: String,
    /// The live lease epoch.
    pub epoch: u64,
    /// The full ref to advance, such as `refs/heads/main`.
    pub ref_name: String,
    /// The value the advance is decided against; `None` means the ref must
    /// not exist yet. It is never discovered for the caller.
    #[serde(default)]
    pub expected_old_oid: Option<String>,
    /// The door base the returned clone URL names, ending in `/git`.
    pub endpoint: String,
}
