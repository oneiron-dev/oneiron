//! Core half of `merge_queue::types`: its store-layer items live in `oneiron_store::merge_queue::types` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::merge_queue::types::*;

use crate::{
    error::Result,
    store::contract_oracle::{AffectedTests, CommandOutput, WorkspaceGraph},
    store::repo_mutation_record::RepoMutationOutcome,
};
use std::path::PathBuf;

#[doc(hidden)]
pub use oneiron_records::merge_queue::types::{CheckPhase, MergeBatch};

#[derive(Debug, Clone)]
pub struct CheckInvocation {
    pub worktree: PathBuf,
    /// Exact commit under test; slow checks use the landed, not speculative, HEAD.
    pub commit: String,
    pub tree: String,
    pub phase: CheckPhase,
    pub selected_tests: AffectedTests,
}

/// Immutable, all-path-tested input. Hosts cannot manufacture this capability.
pub struct TestedBatch {
    pub(super) batch: MergeBatch,
}

impl TestedBatch {
    #[must_use]
    pub fn batch(&self) -> &MergeBatch {
        &self.batch
    }
    #[must_use]
    pub fn tested_tree(&self) -> &str {
        &self.batch.paths.last().expect("staged batch paths").tree
    }
    #[must_use]
    pub fn tested_commit(&self) -> &str {
        &self.batch.paths.last().expect("staged batch paths").commit
    }
}

/// Implement this seam with the host's authenticated proposal/gate path followed
/// by existing per-operation repo mutations under this single-writer hold. A naked GitWire ref move has no accepted
/// repo-mutation receipt. The returned persisted receipt chain must start at this
/// batch's captured snapshot and its resulting full tree must match the tests.
pub trait MergeLanding {
    fn land(
        &mut self,
        permit: &LandingPermit,
        tested: &TestedBatch,
    ) -> Result<Vec<RepoMutationOutcome>>;
}
