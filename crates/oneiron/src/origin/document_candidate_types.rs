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
use crate::code_document::{CodeDocumentFrontier, CodeFileMetadataEdit};
use crate::code_revision::CodeTreeBlob;

/// The validated ref update a receive-pack landed: the proven object store,
/// the full ref and the old and new tips, never a request's own values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReceivedRefSource {
    /// The served object store's hex identity.
    pub object_store: String,
    pub ref_name: String,
    /// The tip the update replaced, 40 lower-hex; `None` for a new ref.
    pub old_oid: Option<String>,
    /// The tip it left, 40 lower-hex; `None` for a deleted ref.
    pub new_oid: Option<String>,
}

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

/// Where an accepted push's candidate stands. Held states keep the source
/// and the accepted push; matching never changes the receive result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CodePushCandidateState {
    /// Received, not matched yet.
    Pending,
    /// No exact base, or more than one.
    HeldBase,
    /// The push it continues has no sealed tested revision yet.
    HeldPredecessor,
    /// No owner review catalog for this repository.
    HeldReviewPolicy,
    /// A shape the reviewed path does not carry: no change, a deleted or
    /// non-commit ref, a non-fast-forward, binary or submodule entries.
    HeldShape,
    /// One all-files proposal awaits review and an owner enqueue.
    Proposed,
    Rejected,
    /// Its proposal is in a merge stack.
    Queued,
    Quarantined,
    RolledBack,
    /// Its proposal applied.
    Landed,
    /// A tested revision binds its complete source.
    Sealed,
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
}

/// A candidate as the owner reads it: a projection of its saved source,
/// proposal, batch and seal rows, never a live head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodePushCandidateView {
    pub candidate: EntityId,
    pub state: CodePushCandidateState,
    /// The engine reason code of a hold.
    pub reason: Option<String>,
    pub base_revision: Option<EntityId>,
    pub fork_session: Option<EntityId>,
    pub proposal_refs: Vec<EntityId>,
    pub batch_refs: Vec<String>,
    pub check_work_refs: Vec<String>,
    pub revision_refs: Vec<EntityId>,
}
