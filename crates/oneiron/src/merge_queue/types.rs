//! Persisted queue records and sealed landing/check boundaries.
use crate::{
    contract_oracle::{AffectedTests, CommandOutput, WorkspaceGraph},
    error::Result,
    repo_mutation::{RepoForkHash, RepoMutationOutcome},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeFile {
    pub path: String,
    /// Exact previously reviewed bytes. Absence means a new path, not a wildcard.
    pub expected: Option<Vec<u8>>,
    /// None deletes a file.
    pub content: Option<Vec<u8>>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeProposal {
    pub id: String,
    pub base_green: String,
    pub files: Vec<MergeFile>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BatchState {
    Queued,
    Staged,
    Ready,
    Landing,
    HeadAdvanced,
    GreenAdvanced,
    Quarantined,
    RollingBack,
    RolledBack,
    Cancelled,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckPhase {
    Fast,
    Slow,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpeculativePath {
    /// Bitset of included proposals. All nonempty subsets are tested before land.
    pub mask: u64,
    pub worktree: PathBuf,
    pub commit: String,
    pub tree: String,
    pub verdict: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quarantine {
    pub proposal_ids: Vec<String>,
    /// A minimal failing group; interactions are not falsely blamed on one member.
    pub failing_mask: u64,
    pub verdict: String,
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
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeQueuePointers {
    pub head: String,
    pub green: String,
    pub pending_slow: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct QueueRecord {
    pub schema_version: u8,
    pub sequence: u64,
    pub baseline_id: String,
    pub graph: WorkspaceGraph,
    pub pointers: MergeQueuePointers,
    pub intent: Option<EffectIntent>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) enum EffectIntent {
    Landing {
        batch: String,
        after_seq: u64,
    },
    Rollback {
        snapshot: RepoForkHash,
        expected_head: String,
    },
}

#[derive(Debug, Clone)]
pub struct CheckInvocation {
    pub worktree: PathBuf,
    pub tree: String,
    pub phase: CheckPhase,
    pub selected_tests: AffectedTests,
}
#[derive(Debug, Clone, Default)]
pub struct CheckReport {
    pub tests_passed: bool,
    pub outputs: BTreeMap<String, CommandOutput>,
}

/// Queue-issued capability. No public constructor or deserializer exists. It is
/// issued only while the repo lock is held after rechecking the expected HEAD.
/// This proves queue readiness, NOT gate approval: the host adapter must still
/// route every proposed edit through its per-operation gate before mutation.
pub struct LandingPermit {
    pub(super) batch_id: String,
    pub(super) repo_identity: String,
    pub(super) expected_head: String,
}
impl LandingPermit {
    #[must_use]
    pub fn batch_id(&self) -> &str {
        &self.batch_id
    }
    #[must_use]
    pub fn repo_identity(&self) -> &str {
        &self.repo_identity
    }
    #[must_use]
    pub fn expected_head(&self) -> &str {
        &self.expected_head
    }
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
