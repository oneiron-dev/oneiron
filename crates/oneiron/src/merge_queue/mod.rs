//! Durable batched speculation over real detached worktrees.
//!
//! Checks never mutate the live repository. Landing needs a host gate adapter and
//! a queue-issued permit under the existing repository single-writer lock. The
//! queue verifies the durable mutation receipt and the complete landed tree.
mod checks;
mod landing;
mod reviewed;
mod staging;
mod storage;
#[cfg(test)]
mod tests;
mod types;

use crate::{
    Vault,
    codebase::RepoRef,
    error::Result,
    git_wire::{GitWire, GitWireRepo},
};
pub use reviewed::ReviewedProposalLanding;
pub use types::{
    BatchState, CheckInvocation, CheckPhase, CheckReport, LandingPermit, MergeBatch, MergeFile,
    MergeLanding, MergeProposal, MergeQueuePointers, Quarantine, SpeculativePath, TestedBatch,
};

pub struct MergeQueue<'a> {
    vault: &'a Vault,
    repo: GitWireRepo,
}

impl<'a> MergeQueue<'a> {
    /// Bind to one proven local object store. `initialize` records its initial
    /// green baseline; reopening never overwrites existing pointers.
    pub fn open(vault: &'a Vault, repo_ref: RepoRef) -> Result<Self> {
        let RepoRef::LocalFolder { path, .. } = &repo_ref else {
            return Err(crate::contract_oracle::invalid(
                "merge queue needs a local repository",
            ));
        };
        let root = std::path::PathBuf::from(path);
        let repo = GitWire::new(vault)?.open_repo(repo_ref, &root)?;
        Ok(Self { vault, repo })
    }
}
