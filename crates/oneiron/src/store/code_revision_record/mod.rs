//! Code revision records, canonical codecs and pure complete-tree vocabulary.

mod types;
pub mod codec;
pub(crate) mod commit_metadata;
pub(crate) mod file_frontiers;
pub(crate) mod tree_codec;
pub(crate) mod tree_inventory;

pub use types::{CodeRevision, CodeRevisionFork, CodeRevisionKind};
pub use tree_inventory::CodeTreeInventory;
pub use crate::store::code_commit_metadata::CodeCommitMetadata;
pub use crate::store::code_tree_blob::CodeTreeBlob;
use crate::entity_id::EntityId;
use crate::store::code_document_values::CodeDocumentFrontier;
use serde::{Deserialize, Serialize};

/// One retired path of a tested queue revision: the exact predecessor it
/// removed, its document if it had one, and the reviewed operation and
/// review that retired it. No producer is admitted before G4 PR2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodePathRetirement {
    pub previous: CodeTreeBlob,
    pub document: Option<CodeDocumentFrontier>,
    pub operation_receipt: EntityId,
    pub review_ref: EntityId,
}
