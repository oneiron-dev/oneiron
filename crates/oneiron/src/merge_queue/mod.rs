//! Durable batched speculation over real detached worktrees.
//!
//! Checks never mutate the live repository. Landing needs a host gate adapter and
//! a queue-issued permit under the existing repository single-writer lock. The
//! queue verifies the durable mutation receipt and the complete landed tree.
mod check_execute;
mod check_inputs;
mod check_requests;
mod check_store;
mod check_tree;
mod checks;
mod driver;
mod driver_materialize;
mod driver_store;
mod driver_types;
mod initialize;
mod landing;
mod mirror_green;
mod plan;
mod reviewed;
mod run;
mod staging;
mod storage;
mod tested;
mod tested_export;
mod tested_store;
mod tested_types;
#[cfg(test)]
mod tests;
mod types;

use crate::{
    Vault,
    codebase::RepoRef,
    error::Result,
    git_wire::{GitWire, GitWireRepo},
};
// The pinned-plan checker (FIX 6868).
pub use check_inputs::{
    QUEUE_CHECK_CANDIDATE_PREFIX, QueueCheckEnvironment, QueueCheckExecution, QueueCheckFile,
    QueueCheckHold, QueueCheckHoldReason, QueueCheckHost, QueueCheckInputs, QueueCheckInvocation,
    QueueCheckLimits, QueueCheckNeed, QueueCheckReceipt, QueueCheckRun, QueueCheckTarget,
    QueueCheckTreeSource, QueueCommandReceipt,
};
pub use check_store::{
    DEFAULT_QUEUE_CHECK_CONCURRENCY, QUEUE_CHECK_ATTEMPT_KIND, QueueCheckConfiguration,
    QueueCheckInitStage, QueueCheckLease, QueueCheckRequest, QueueCheckStatus, QueueCheckWork,
};
// The restart driver and overlap handoff (FIX 6868, G2 PR2).
pub(crate) use driver_types::QueueStageOverlap;
pub use driver_types::{
    QueueBatchDrive, QueueConflictLink, QueueConflictView, QueueDriveHold, QueueDriveHoldReason,
    QueueDriveOutcome, QueueDrivePass, QueueDriveStatus, QueueDriveView, QueueDriverTarget,
    QueueSurvivorLink, QueueWork,
};
pub use plan::{FrozenCheckPlan, REPO_CHECK_PLAN_PATH, RepoCheckPlan};
pub use reviewed::ReviewedProposalLanding;
pub use run::{RepoQueueOrder, RepoQueuePredecessor};
// The tested-revision seal at green (FIX 6868, G2 PR3).
pub(crate) use tested_types::QueueRevisionSeal;
pub use tested_types::{
    GreenQueueRevision, QueueAppliedSource, QueueExportHold, QueueExportHoldReason,
    QueueGreenExportView, QueueReceiptLink, QueueRevisionIntent, QueueRevisionLink,
    QueueSealTarget, QueueTestedRevision, QueueTestedTarget,
};
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
