//! The retained received-ref source and its accepted-push candidate (FIX
//! 6869, G4 PR2).
//!
//! Every ref one receive-pack updates keeps one immutable source row: the
//! validated update, the time it was first received and the file operations
//! it carried, even when it changed nothing. Matching later attaches one
//! candidate: its deterministic id and source digest, the base, fork and
//! all-files proposal it resolved to (frozen once, never rebound), or the
//! typed hold that keeps it. The receive result never depends on it.
use serde::{Deserialize, Serialize};

use super::ReceivedFileOperation;
use crate::EntityId;
use crate::store::code_document_values::{CodeDocumentFrontier, CodeFileMetadataEdit};
use crate::store::code_tree_blob::CodeTreeBlob;

#[doc(hidden)]
pub use oneiron_verb_wire::origin::document_candidate_types::{
    CodePushCandidateState, CodePushCandidateView, ReceivedRefSource,
};

/// One received ref's retained row: its source, when it was first
/// received, its file operations, and the candidate matching attached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceivedRefIngress {
    pub source: ReceivedRefSource,
    pub received_at: u64,
    pub operations: Vec<ReceivedFileOperation>,
    pub candidate: Option<CodePushCandidate>,
}

/// Names one retained received ref. A domain identifier, never a request.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReceivedCandidateRef {
    pub object_store: String,
    pub provenance: EntityId,
    pub ref_name: String,
}

/// A held candidate's state and engine reason code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodePushCandidateHold {
    pub state: CodePushCandidateState,
    pub reason: String,
}

/// One file of a resolved candidate: its source operation, its exact base
/// and incoming entries, the base document if it had one, its reviewed
/// metadata and the document operation it lowers to, if any.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedCandidateFile {
    pub source_operation: EntityId,
    pub path: String,
    pub before: Option<CodeTreeBlob>,
    pub after: Option<CodeTreeBlob>,
    pub base_frontier: Option<CodeDocumentFrontier>,
    pub metadata_edit: CodeFileMetadataEdit,
    pub document_operation: Option<EntityId>,
}

/// What a candidate resolved to, frozen at its first resolution: the
/// exact base revision and its checked commit, the admitted publication,
/// the fork and the ONE proposal carrying every file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedPushCandidate {
    pub base_revision: EntityId,
    pub base_commit: String,
    pub base_inventory_digest: [u8; 32],
    pub snapshot_anchor: Option<EntityId>,
    pub publication: EntityId,
    pub new_tree: String,
    pub fork_session: EntityId,
    pub proposal_id: EntityId,
    pub resolved_at: u64,
    pub files: Vec<ResolvedCandidateFile>,
}

/// The candidate one source row carries: its id and source digest, its
/// frozen resolution once there is one, else its last hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodePushCandidate {
    pub candidate: EntityId,
    pub source_digest: [u8; 32],
    pub resolved: Option<ResolvedPushCandidate>,
    pub hold: Option<CodePushCandidateHold>,
    /// A candidate received from a masked copy: its immutable projection
    /// pins and typed causes (FIX 7608 2b-ii); none for every other push.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projected: Option<super::RepoProjectedCandidatePins>,
}
