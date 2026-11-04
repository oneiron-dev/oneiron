//! Index-only handles to scoped repository instruction files.

use crate::entity_id::EntityId;

/// One instruction file in one snapshot, and the returned units it governs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CodeInstructionHandle {
    /// The CODE_ARTIFACT whose snapshot holds the file.
    pub code_artifact_id: EntityId,
    /// Canonical pinned repository ref of that snapshot.
    pub repo_ref: String,
    pub path: String,
    /// Lower-case hex of the file's snapshot content hash.
    pub content_hash: String,
    /// The returned units on whose ancestor path the file sits.
    pub units: Vec<EntityId>,
}
