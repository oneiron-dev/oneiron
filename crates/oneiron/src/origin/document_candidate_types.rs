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

#[doc(hidden)]
pub use oneiron_records::origin::document_candidate_types::{
    CodePushCandidate, CodePushCandidateHold, ReceivedRefIngress, ResolvedCandidateFile,
    ResolvedPushCandidate,
};

/// Names one retained received ref. A domain identifier, never a request.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReceivedCandidateRef {
    pub object_store: String,
    pub provenance: EntityId,
    pub ref_name: String,
}
