//! Core half of `merge_queue::types`: its store-layer items live in `oneiron_store::merge_queue::types` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::merge_queue::types::*;

use crate::store::repo_fork::RepoForkHash;
use crate::{
    error::Result,
    store::contract_oracle::{AffectedTests, CommandOutput, WorkspaceGraph},
    store::repo_mutation_record::RepoMutationOutcome,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckPhase {
    Fast,
    Slow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeBatch {
    pub schema_version: u8,
    pub id: String,
    pub expected_head: String,
    pub base_green: String,
    pub baseline_id: String,
    pub proposals: Vec<MergeProposal>,
    pub state: BatchState,
    pub paths: Vec<SpeculativePath>,
    pub pre_snapshot: Option<RepoForkHash>,
    pub landed_head: Option<String>,
    pub slow_verdict: Option<String>,
    pub quarantine: Option<Quarantine>,
    pub selected_tests: AffectedTests,
    /// A leased run's accepted entry and the declarations it waits behind
    /// (FIX 6867); `None` for an owner or trusted batch, which waits on none.
    pub run_order: Option<super::RepoQueueOrder>,
    /// What the automatic driver decided for it (FIX 6868, G2 PR2); `None`
    /// until the driver acts on it. An owner's call needs none.
    pub drive: Option<super::QueueBatchDrive>,
}

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
