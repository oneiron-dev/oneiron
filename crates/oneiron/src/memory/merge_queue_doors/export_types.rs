//! `vault.code.merge_queue.export_green`'s request (FIX 6868, G2 PR3). It
//! names the queue, the owner's live checkout and the publication target.
//! It never names a revision, tree, frontier, verdict, pass or actor: the
//! engine resolves the queue's current sealed green itself. The answer is
//! the unchanged `vault.code.export` result.
use serde::{Deserialize, Serialize};

use crate::EntityId;

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
