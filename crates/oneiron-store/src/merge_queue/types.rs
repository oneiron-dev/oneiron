//! Persisted queue records and sealed landing/check boundaries.
use crate::contract_oracle::graph::AffectedTests;
use crate::contract_oracle::graph::WorkspaceGraph;
use crate::contract_oracle::types::CommandOutput;
use crate::repo_fork::RepoForkHash;
use crate::repo_mutation_record::RepoMutationOutcome;
use oneiron_base::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeFile {
    pub path: String,
    /// The previously reviewed base. Absence means a new path, not a wildcard.
    pub expected: Option<MergeFileExpected>,
    /// None deletes a file.
    pub content: Option<Vec<u8>>,
    /// A received bundle's reviewed exact Git state change of this path
    /// (G4 PR2); `None` on every ordinary file, which stages as before.
    pub metadata_edit: Option<crate::code_document_values::CodeFileMetadataEdit>,
}

/// The base state a queue file is checked against (FIX 10974).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MergeFileExpected {
    /// The exact previously reviewed bytes.
    Bytes(Vec<u8>),
    /// The BLAKE3 of bytes a withheld base keeps out of every queue row (a
    /// secret remediation's file), compared by hash against the tested tree.
    Blake3([u8; 32]),
}

impl MergeFileExpected {
    /// Whether `actual` is this state.
    #[must_use]
    pub fn holds(&self, actual: &[u8]) -> bool {
        match self {
            Self::Bytes(bytes) => bytes.as_slice() == actual,
            Self::Blake3(hash) => blake3::hash(actual).as_bytes() == hash,
        }
    }

    /// The BLAKE3 of the state, so two states compare whatever they hold.
    #[must_use]
    pub fn blake3(&self) -> [u8; 32] {
        match self {
            Self::Bytes(bytes) => *blake3::hash(bytes).as_bytes(),
            Self::Blake3(hash) => *hash,
        }
    }

    /// The bytes this state keeps in a row.
    #[must_use]
    pub fn stored_len(&self) -> usize {
        match self {
            Self::Bytes(bytes) => bytes.len(),
            Self::Blake3(hash) => hash.len(),
        }
    }
}

impl MergeFile {
    /// Whether `actual` (`None`: no file) is the base this file expects,
    /// compared by the state it holds.
    #[must_use]
    pub fn expects(&self, actual: Option<&[u8]>) -> bool {
        match (&self.expected, actual) {
            (None, None) => true,
            (Some(expected), Some(actual)) => expected.holds(actual),
            _ => false,
        }
    }
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
pub struct MergeQueuePointers {
    pub head: String,
    pub green: String,
    pub pending_slow: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueRecord {
    pub schema_version: u8,
    pub sequence: u64,
    pub baseline_id: String,
    pub graph: WorkspaceGraph,
    pub pointers: MergeQueuePointers,
    pub intent: Option<EffectIntent>,
    /// A served import's queue: its binding init work's full key, saved
    /// with the initial pointers (FIX 6869). `None` for a native queue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_init_work: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EffectIntent {
    Landing {
        batch: String,
        after_seq: u64,
    },
    Rollback {
        snapshot: RepoForkHash,
        expected_head: String,
    },
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
    pub batch_id: String,
    pub repo_identity: String,
    pub expected_head: String,
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
