//! Moved from `crates/oneiron/src/origin/document_candidate_types.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::code_document_values::CodeDocumentFrontier;
use oneiron_store::code_document_values::CodeFileMetadataEdit;
use oneiron_store::code_tree_blob::CodeTreeBlob;
pub use oneiron_verb_wire::origin::document_candidate_types::CodePushCandidateState;
pub use oneiron_verb_wire::origin::document_candidate_types::CodePushCandidateView;
pub use oneiron_verb_wire::origin::document_candidate_types::ReceivedRefSource;
use oneiron_verb_wire::origin::document_ingress::ReceivedFileOperation;
use serde::Deserialize;
use serde::Serialize;

/// One received ref's retained row: its source, when it was first
/// received, its file operations, and the candidate matching attached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceivedRefIngress {
    pub source: ReceivedRefSource,
    pub received_at: u64,
    pub operations: Vec<ReceivedFileOperation>,
    pub candidate: Option<CodePushCandidate>,
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
