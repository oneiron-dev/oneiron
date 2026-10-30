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
    /// A secret remediation's file its base withholds: the BLAKE3 of the
    /// bytes the remediation read at the pinned commit, which the merge
    /// queue checks the tested tree against, so no old byte is stored
    /// (FIX 10974).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withheld_base_blake3: Option<[u8; 32]>,
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
            withheld_base_blake3: None,
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
            RepoProposalOperation::CommitFiles => "commit_files",
        }
    }

    /// Whether it is a file bundle, received or native: many files, each
    /// with its exact state change, landed as one commit by its queue.
    #[must_use]
    pub fn is_file_bundle(&self) -> bool {
        matches!(
            self.operation,
            RepoProposalOperation::ReceivedFiles { .. } | RepoProposalOperation::CommitFiles
        )
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

    /// Whether it is a received bundle whose every file names the source
    /// operation it was accepted from: a queue overlap hands it off like a
    /// whole-file proposal (FIX 9976).
    #[must_use]
    pub(crate) fn is_source_bound_received(&self) -> bool {
        self.received_candidate().is_some()
            && !self.files.is_empty()
            && self
                .files
                .iter()
                .all(|file| file.source_operation.is_some() && file.metadata_edit.is_some())
    }

    /// The oplog subject it lands under: an ordinary file's path, a
    /// received bundle's candidate id, or a native bundle's message.
    #[must_use]
    pub(crate) fn operation_subject(&self) -> String {
        match (&self.operation, self.files.as_slice()) {
            (RepoProposalOperation::ReceivedFiles { candidate }, _) => candidate.to_hex(),
            (RepoProposalOperation::CommitFiles, _) => {
                crate::repo_mutation::bundle::bundle_operation_subject(&self.message)
            }
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

/// The typed refusal of a file bundle outside its queue: a received
/// bundle's own, or a native bundle's.
pub(super) fn bundle_queue_only(row: &RepoProposal) -> Error {
    if row.received_candidate().is_some() {
        return received_bundle_queue_only();
    }
    native_bundle_queue_only()
}

/// The typed refusal of a native file bundle outside its queue: it names
/// how the bundle lands.
pub(in crate::repo_mutation) fn native_bundle_queue_only() -> Error {
    Error::Refused(
        "file_bundle_queue_only: a reviewed file bundle lands through its repository's merge \
         queue; enqueue it with vault.code.merge_queue.enqueue, then land it with \
         vault.code.merge_queue.land_reviewed"
            .to_owned(),
    )
}
