//! Repository mutation operations, journal outcomes and conflict records.

use crate::entity_id::EntityId;
use crate::error::{CodeError, Error, Result};
use crate::store::code_snapshot::RepoRef;
use std::path::PathBuf;

pub use crate::store::repo_fork::RepoForkHash;

pub const REPO_MUTATION_ALLOWED_OPERATION_KINDS: [&str; 8] = [
    "commit_file",
    "create_worktree",
    "record_conflict",
    "remove_worktree",
    "recover_snapshot",
    "resolve_conflict_file",
    "received_files",
    "commit_files",
];
pub const REPO_MUTATION_FORBIDDEN_GIT_COMMANDS: [&str; 3] =
    ["git clean", "git reset --hard", "git checkout -- ."];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RepoMutationStatus {
    Prepared,
    Applied,
    Failed,
}

impl RepoMutationStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Applied => "applied",
            Self::Failed => "failed",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "applied" => Ok(Self::Applied),
            "failed" => Ok(Self::Failed),
            _ => Err(Error::Code(CodeError::InvalidRepoMutationRecord(
                "repo mutation status must be prepared, applied, or failed",
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RepoMutationOperation {
    CommitFile {
        path: String,
        content: Vec<u8>,
        message: String,
    },
    CreateWorktree {
        worktree_path: PathBuf,
        base_ref: String,
    },
    RecordConflict {
        branch_subject: EntityId,
        branch_name: String,
        ours_ref: String,
        theirs_ref: String,
    },
    RemoveWorktree {
        worktree_path: PathBuf,
    },
    RecoverSnapshot {
        fork_hash: RepoForkHash,
    },
    ResolveConflictFile {
        branch_subject: EntityId,
        open_conflict_claim_id: EntityId,
        branch_name: String,
        path: String,
        content: Vec<u8>,
        message: String,
    },
    /// Every file of one accepted pushed ref update, landed as ONE reviewed
    /// commit (G4 PR2). Its bytes and modes resolve from the stored bundle
    /// the candidate names, never from this request.
    ReceivedFiles {
        candidate: EntityId,
        source_operations: Vec<EntityId>,
        message: String,
    },
    /// Every file of one native reviewed bundle, landed as ONE commit
    /// through its merge queue (FIX 7608 slice 5). Each file's exact
    /// state change is the one its proposal stored.
    CommitFiles {
        files: Vec<RepoBundleFile>,
        message: String,
    },
}

/// One file of a native reviewed bundle: its path, its new bytes (`None`
/// removes it) and its Git mode once present (`None` keeps the base's
/// mode, or a regular file's for a new path).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RepoBundleFile {
    pub path: String,
    pub content: Option<Vec<u8>>,
    pub mode: Option<u32>,
}

impl RepoBundleFile {
    #[must_use]
    pub fn new(path: String, content: Option<Vec<u8>>, mode: Option<u32>) -> Self {
        Self {
            path,
            content,
            mode,
        }
    }
}

impl RepoMutationOperation {
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::CommitFile { .. } => "commit_file",
            Self::CreateWorktree { .. } => "create_worktree",
            Self::RecordConflict { .. } => "record_conflict",
            Self::RemoveWorktree { .. } => "remove_worktree",
            Self::RecoverSnapshot { .. } => "recover_snapshot",
            Self::ResolveConflictFile { .. } => "resolve_conflict_file",
            Self::ReceivedFiles { .. } => "received_files",
            Self::CommitFiles { .. } => "commit_files",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RepoCommitProvenance {
    pub commit_sha: String,
    pub claim_id: EntityId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RepoMutationOplogEntry {
    pub repo_ref: RepoRef,
    pub seq: u64,
    pub operation_kind: String,
    pub operation_subject: Option<String>,
    /// None when no actor was recorded, or once that actor was erased (FIX 3520).
    pub actor_id: Option<EntityId>,
    /// The class a host stamped beside the actor (FIX 6867); `None` for a
    /// trusted or owner request.
    pub actor_class: Option<crate::edge::EdgeActorClass>,
    pub session_id: Option<EntityId>,
    pub started_at_ms: u64,
    pub finished_at_ms: Option<u64>,
    pub pre_action_fork_hash: RepoForkHash,
    pub expected_post_action_fork_hash: Option<RepoForkHash>,
    /// The commit a committing write leaves HEAD at, recorded before it
    /// applies (FIX 7705): a queue source put back mid-landing stands at the
    /// exact applied prefix. `None` for a direct write.
    pub post_commit: Option<String>,
    pub status: RepoMutationStatus,
    pub failure: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RepoMutationOutcome {
    pub entry: RepoMutationOplogEntry,
    pub repo_conflict_claim_id: Option<EntityId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RepoConflictClaim {
    pub claim_id: EntityId,
    pub subject: EntityId,
    pub repo_ref: RepoRef,
    pub branch: String,
    pub base_tree: String,
    pub ours_tree: String,
    pub theirs_tree: String,
    pub conflicted_paths: Vec<String>,
    pub proposals: Vec<EntityId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RepoConflictResolutionClaim {
    pub claim_id: EntityId,
    pub subject: EntityId,
    pub repo_ref: RepoRef,
    pub branch: String,
    pub open_conflict_claim_id: EntityId,
    pub resolved_tree: String,
    pub resolved_paths: Vec<String>,
}
