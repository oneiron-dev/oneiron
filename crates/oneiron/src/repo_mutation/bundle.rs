//! A reviewed file bundle's queue preparation: ONE staged commit carrying
//! every file of the bundle (moved from `queue.rs`, FIX 7608 slice 5).
use std::path::Path;

use super::queue::PreparedRepoMutationExecution;
use super::types::{RepoMutationOperation, RepoMutationRequest};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

impl Vault {
    /// A received bundle's ONE staged commit: its stored files' exact tree
    /// change under its own message, prepared on the checkout's HEAD.
    pub(super) fn prepare_received_files_execution(
        &self,
        repo_root: &Path,
        request: &RepoMutationRequest,
        proposal: Option<EntityId>,
    ) -> Result<PreparedRepoMutationExecution> {
        let RepoMutationOperation::ReceivedFiles { message, .. } = &request.operation else {
            return Err(Error::InvariantViolation("not a received push bundle"));
        };
        let row = self
            .repo_proposal(proposal.ok_or(Error::InvariantViolation(
                "a received bundle lands under its proposal",
            ))?)?
            .ok_or(Error::EntityNotFound)?;
        let edits = super::received_file::tree::received_tree_edits(&row.files)?;
        let commit =
            super::received_file::tree::prepare_received_files_commit(repo_root, &edits, message)?;
        Ok(PreparedRepoMutationExecution::ReceivedFiles { commit, edits })
    }
}
