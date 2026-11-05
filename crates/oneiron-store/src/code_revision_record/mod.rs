//! Code revision records, canonical codecs and pure complete-tree vocabulary.

pub use crate::code_commit_metadata::CodeCommitMetadata;
use crate::code_document_values::CodeDocumentFrontier;
pub use crate::code_tree_blob::CodeTreeBlob;
use oneiron_contracts::entity_id::EntityId;
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

pub mod commit_metadata;
pub mod file_frontiers;
pub mod tree_codec;
