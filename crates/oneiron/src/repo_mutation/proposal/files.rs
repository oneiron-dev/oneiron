//! A proposal's reviewed files (G4 PR2): an ordinary operation's one file,
//! or every file of a received push bundle, and the accessors that keep
//! each consumer honest about which it reads.
use serde::{Deserialize, Serialize};

use super::{RepoProposal, RepoProposalOperation, invalid};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// One reviewed file of a proposal. An ordinary operation's file has its
/// bytes and no source; a received bundle's names its source operation
/// and its exact Git state change, and `None` bytes remove it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoProposedFile {
    pub path: String,
    pub content: Option<Vec<u8>>,
    pub source_operation: Option<EntityId>,
    pub metadata_edit: Option<crate::code_document::CodeFileMetadataEdit>,
}

impl RepoProposedFile {
    /// An ordinary operation's one file.
    #[must_use]
    pub fn ordinary(path: String, content: Vec<u8>) -> Self {
        Self {
            path,
            content: Some(content),
            source_operation: None,
            metadata_edit: None,
        }
    }
}

impl RepoProposal {
    /// The one file an ordinary operation changes, with its bytes. A
    /// received bundle has no single file and refuses by name.
    ///
    /// # Errors
    /// A received bundle, or a malformed ordinary row.
    pub(crate) fn ordinary_file(&self) -> Result<(&str, &[u8])> {
        if matches!(self.operation, RepoProposalOperation::ReceivedFiles { .. }) {
            return Err(invalid(
                "a received push bundle has no single reviewed file",
            ));
        }
        match self.files.as_slice() {
            [file] if file.source_operation.is_none() && file.metadata_edit.is_none() => file
                .content
                .as_deref()
                .map(|content| (file.path.as_str(), content))
                .ok_or(invalid("an ordinary proposal file has its bytes")),
            _ => Err(invalid("an ordinary proposal changes exactly one file")),
        }
    }

    /// The repo mutation kind it lands as.
    #[must_use]
    pub fn operation_kind(&self) -> &'static str {
        match self.operation {
            RepoProposalOperation::CommitFile => "commit_file",
            RepoProposalOperation::ResolveConflictFile { .. } => "resolve_conflict_file",
            RepoProposalOperation::ReceivedFiles { .. } => "received_files",
        }
    }

    /// The received candidate a bundle carries, if this is one.
    #[must_use]
    pub fn received_candidate(&self) -> Option<EntityId> {
        match self.operation {
            RepoProposalOperation::ReceivedFiles { candidate } => Some(candidate),
            _ => None,
        }
    }

    /// Every path the proposal reviews, in its order.
    #[must_use]
    pub fn paths(&self) -> Vec<&str> {
        self.files.iter().map(|file| file.path.as_str()).collect()
    }

    /// The oplog subject it lands under: an ordinary file's path, or a
    /// received bundle's candidate id.
    #[must_use]
    pub(crate) fn operation_subject(&self) -> String {
        match (&self.operation, self.files.as_slice()) {
            (RepoProposalOperation::ReceivedFiles { candidate }, _) => candidate.to_hex(),
            (_, [file]) => file.path.clone(),
            _ => String::new(),
        }
    }
}

/// The typed refusal of a received push bundle outside its queue: it
/// names how the bundle lands.
pub(in crate::repo_mutation) fn received_bundle_queue_only() -> Error {
    Error::Refused(
        "received_bundle_queue_only: a received push bundle lands through its repository's \
         merge queue; enqueue it with vault.code.merge_queue.enqueue, then land it with \
         vault.code.merge_queue.land_reviewed"
            .to_owned(),
    )
}
