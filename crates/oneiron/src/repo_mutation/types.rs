use std::path::PathBuf;

use crate::codebase::RepoRef;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

pub type RepoForkHash = [u8; 32];

pub const REPO_MUTATION_ALLOWED_OPERATION_KINDS: [&str; 6] = [
    "commit_file",
    "create_worktree",
    "record_conflict",
    "remove_worktree",
    "recover_snapshot",
    "resolve_conflict_file",
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

    pub(super) fn parse(value: &str) -> Result<Self> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "applied" => Ok(Self::Applied),
            "failed" => Ok(Self::Failed),
            _ => Err(Error::InvalidRepoMutationRecord(
                "repo mutation status must be prepared, applied, or failed",
            )),
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
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RepoMutationRequest {
    pub repo_ref: RepoRef,
    pub actor_id: Option<EntityId>,
    pub session_id: Option<EntityId>,
    pub provenance_claim_id: Option<EntityId>,
    pub operation: RepoMutationOperation,
}

impl RepoMutationRequest {
    #[must_use]
    pub fn new(repo_ref: RepoRef, operation: RepoMutationOperation) -> Self {
        Self {
            repo_ref,
            actor_id: None,
            session_id: None,
            provenance_claim_id: None,
            operation,
        }
    }

    #[must_use]
    pub fn with_actor_id(mut self, actor_id: EntityId) -> Self {
        self.actor_id = Some(actor_id);
        self
    }

    #[must_use]
    pub fn with_session_id(mut self, session_id: EntityId) -> Self {
        self.session_id = Some(session_id);
        self
    }

    #[must_use]
    pub fn with_provenance_claim_id(mut self, claim_id: EntityId) -> Self {
        self.provenance_claim_id = Some(claim_id);
        self
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
    pub actor_id: Option<EntityId>,
    pub session_id: Option<EntityId>,
    pub started_at_ms: u64,
    pub finished_at_ms: Option<u64>,
    pub pre_action_fork_hash: RepoForkHash,
    pub expected_post_action_fork_hash: Option<RepoForkHash>,
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
