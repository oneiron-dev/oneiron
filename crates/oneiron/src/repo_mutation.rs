use std::collections::{BTreeSet, HashMap};
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, PREDICATE_CONFLICT_OPEN,
    PREDICATE_CONFLICT_RESOLVED, decode_claim_body, encode_claim_body,
};
use crate::codebase::CODEBASE_COMMIT_HASH_HEX_LEN;
use crate::codebase::{CODEBASE_FILE_PATH_MAX_BYTES, RepoRef};
use crate::error::{Error, Result};
use crate::types::{ENTITY_TYPE_CLAIM, EdgeKind, EntityId, TimeRange, Vad};

use rmpv::Value;

pub type RepoForkHash = [u8; 32];

pub const REPO_MUTATION_OPLOG_SCHEMA_VERSION: u8 = 1;
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
pub const REPO_CONFLICT_CLAIM_VALUE_SCHEMA_VERSION: u8 = 1;
pub const REPO_CONFLICT_OPEN_VALUE_KEYS: [&str; 8] = [
    "schema_version",
    "kind",
    "repo_ref",
    "branch",
    "base_tree",
    "ours_tree",
    "theirs_tree",
    "conflicted_paths",
];
pub const REPO_CONFLICT_RESOLUTION_VALUE_KEYS: [&str; 7] = [
    "schema_version",
    "kind",
    "repo_ref",
    "branch",
    "open_conflict_claim_id",
    "resolved_tree",
    "resolved_paths",
];

const REPO_MUTATION_SEQ_KEY_PREFIX: &[u8] = b"repo_mutation:seq:v1:";
const REPO_MUTATION_OPLOG_KEY_PREFIX: &[u8] = b"repo_mutation:oplog:v1:";
const REPO_MUTATION_SNAPSHOT_KEY_PREFIX: &[u8] = b"repo_mutation:snapshot:v1:";
const REPO_CONFLICT_KIND_REPO_BRANCH: &str = "repo_branch";
const MAX_REPO_CONFLICT_PATHS: usize = 1024;
const MAX_COMMIT_MESSAGE_BYTES: usize = 4096;
const MAX_BASE_REF_BYTES: usize = 256;
const MAX_REPO_MUTATION_FAILURE_BYTES: usize = 4096;
const MAX_REPO_MUTATION_SNAPSHOT_FILES: usize = 100_000;
const MAX_REPO_MUTATION_SNAPSHOT_TOTAL_BYTES: u64 = 128 * 1024 * 1024;
const MAX_REPO_MUTATION_SNAPSHOT_FILE_BYTES: u64 = 32 * 1024 * 1024;
const REPO_MUTATION_LOCK_FILE_NAME: &str = "oneiron-repo-mutation.lock";

static REPO_MUTATION_LOCKS: LazyLock<Mutex<HashMap<String, Arc<Mutex<()>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static REPO_MUTATION_WORKTREE_COUNTER: AtomicU64 = AtomicU64::new(1);

#[cfg(unix)]
struct RepoMutationFileLock {
    file: fs::File,
}

#[cfg(not(unix))]
struct RepoMutationFileLock;

#[cfg(unix)]
impl Drop for RepoMutationFileLock {
    fn drop(&mut self) {
        // SAFETY: `file.as_raw_fd()` is a live descriptor held by this guard.
        // `flock(LOCK_UN)` releases the advisory lock before the descriptor is
        // closed; ignoring unlock errors is acceptable during drop.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

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

    fn parse(value: &str) -> Result<Self> {
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
    pub operation: RepoMutationOperation,
}

impl RepoMutationRequest {
    #[must_use]
    pub fn new(repo_ref: RepoRef, operation: RepoMutationOperation) -> Self {
        Self {
            repo_ref,
            actor_id: None,
            session_id: None,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct RepoConflictOpenValue {
    repo_ref: RepoRef,
    branch: String,
    base_tree: String,
    ours_tree: String,
    theirs_tree: String,
    conflicted_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RepoConflictResolutionValue {
    repo_ref: RepoRef,
    branch: String,
    open_conflict_claim_id: EntityId,
    resolved_tree: String,
    resolved_paths: Vec<String>,
}

#[derive(Debug, Clone)]
struct PreparedRepoMutation {
    repo_key_hash: String,
    seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredRepoMutationOplogEntry {
    schema_version: u8,
    repo_ref: String,
    seq: u64,
    operation_kind: String,
    operation_subject: Option<String>,
    actor_id: Option<[u8; 16]>,
    session_id: Option<[u8; 16]>,
    started_at_ms: u64,
    finished_at_ms: Option<u64>,
    pre_action_fork_hash: RepoForkHash,
    status: String,
    failure: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredRepoSnapshot {
    schema_version: u8,
    head: Option<String>,
    entries: Vec<StoredRepoSnapshotEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredRepoSnapshotEntry {
    path: String,
    kind: StoredRepoSnapshotEntryKind,
    executable: bool,
    content: Vec<u8>,
    symlink_target: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredRepoSnapshotEntryKind {
    File,
    Symlink,
}

#[derive(Debug, Default)]
struct SnapshotStats {
    files: usize,
    total_bytes: u64,
}

impl Vault {
    /// Runs a named repo mutation through the single-writer queue.
    ///
    /// The queue records a content-addressed pre-action snapshot and a durable
    /// oplog row before the mutation reaches git. The queue also holds a
    /// per-repo advisory lock in Git's common directory, so independent engine
    /// processes serialize through the same repo mutation point. A process death
    /// after the pre-action row leaves the row in `prepared`; the next queued
    /// non-recovery mutation automatically remounts prepared rows first, and
    /// callers can explicitly invoke [`Vault::recover_prepared_repo_mutations`].
    pub fn apply_repo_mutation(&self, request: RepoMutationRequest) -> Result<RepoMutationOutcome> {
        validate_operation(&request.operation)?;
        let repo_root = resolve_mutable_repo_root(&request.repo_ref)?;
        let repo_ref = canonical_repo_ref_for_root(&request.repo_ref, &repo_root)?;
        let common_dir = git_common_dir(&repo_root)?;
        let lock_key = repo_lock_key(&common_dir)?;
        let lock = repo_mutation_lock(&lock_key)?;
        let _guard = lock
            .lock()
            .map_err(|_| Error::ConcurrentWrite("repo mutation lock poisoned"))?;
        let _file_guard = repo_mutation_file_lock(&common_dir)?;

        if !matches!(
            request.operation,
            RepoMutationOperation::RecoverSnapshot { .. }
        ) {
            self.recover_prepared_repo_mutations_locked(&repo_ref, &repo_root)?;
        }

        let prepared = self.prepare_repo_mutation(&repo_ref, &request, &repo_root)?;
        match execute_repo_mutation(self, &repo_ref, &repo_root, &request.operation) {
            Ok(repo_conflict_claim_id) => {
                let entry = self.finish_repo_mutation(
                    &prepared,
                    RepoMutationStatus::Applied,
                    None,
                    now_millis(),
                )?;
                Ok(RepoMutationOutcome {
                    entry,
                    repo_conflict_claim_id,
                })
            }
            Err(error) => {
                let failure = truncate_failure(&error.to_string());
                let _ = self.finish_repo_mutation(
                    &prepared,
                    RepoMutationStatus::Failed,
                    Some(failure),
                    now_millis(),
                );
                Err(error)
            }
        }
    }

    /// Restores a repo working tree from a previously recorded pre-action
    /// forkHash, through the same mutation queue and oplog invariant.
    pub fn recover_repo_snapshot(
        &self,
        repo_ref: &RepoRef,
        fork_hash: RepoForkHash,
    ) -> Result<RepoMutationOutcome> {
        self.apply_repo_mutation(RepoMutationRequest::new(
            repo_ref.clone(),
            RepoMutationOperation::RecoverSnapshot { fork_hash },
        ))
    }

    /// Detects prepared repo mutation oplog rows and remounts each recorded
    /// pre-action forkHash through the same queue.
    ///
    /// Successfully recovered prepared rows are marked `failed` with a recovery
    /// note, and each remount also receives its own applied `recover_snapshot`
    /// oplog row.
    pub fn recover_prepared_repo_mutations(
        &self,
        repo_ref: &RepoRef,
    ) -> Result<Vec<RepoMutationOutcome>> {
        let repo_root = resolve_mutable_repo_root(repo_ref)?;
        let canonical = canonical_repo_ref_for_root(repo_ref, &repo_root)?;
        let common_dir = git_common_dir(&repo_root)?;
        let lock_key = repo_lock_key(&common_dir)?;
        let lock = repo_mutation_lock(&lock_key)?;
        let _guard = lock
            .lock()
            .map_err(|_| Error::ConcurrentWrite("repo mutation lock poisoned"))?;
        let _file_guard = repo_mutation_file_lock(&common_dir)?;
        self.recover_prepared_repo_mutations_locked(&canonical, &repo_root)
    }

    /// Reads the durable oplog for a repo in sequence order.
    pub fn repo_mutation_oplog(&self, repo_ref: &RepoRef) -> Result<Vec<RepoMutationOplogEntry>> {
        let repo_root = resolve_mutable_repo_root(repo_ref)?;
        let canonical = canonical_repo_ref_for_root(repo_ref, &repo_root)?;
        self.repo_mutation_oplog_for_canonical(&canonical)
    }

    /// Lists active typed repo conflict claims attached to a branch subject.
    pub fn repo_conflict_claims(
        &self,
        branch_subject: &EntityId,
    ) -> Result<Vec<RepoConflictClaim>> {
        let mut claims = Vec::new();
        for claim_id in self.claims_for_subject(branch_subject)? {
            let Some(body) = self.get_claim(&claim_id)? else {
                continue;
            };
            if body.predicate != PREDICATE_CONFLICT_OPEN
                || body.lifecycle != ClaimLifecycleStatus::Active
                || body.subject != ClaimSubject::Entity(*branch_subject)
            {
                continue;
            }
            let Ok(value) = decode_repo_conflict_open_value(&body.value) else {
                continue;
            };
            claims.push(RepoConflictClaim {
                claim_id,
                subject: *branch_subject,
                repo_ref: value.repo_ref,
                branch: value.branch,
                base_tree: value.base_tree,
                ours_tree: value.ours_tree,
                theirs_tree: value.theirs_tree,
                conflicted_paths: value.conflicted_paths,
            });
        }
        claims.sort_by(|left, right| {
            left.branch
                .cmp(&right.branch)
                .then_with(|| left.claim_id.as_bytes().cmp(right.claim_id.as_bytes()))
        });
        Ok(claims)
    }

    /// Lists typed conflict resolution claims attached to a branch subject.
    pub fn repo_conflict_resolution_claims(
        &self,
        branch_subject: &EntityId,
    ) -> Result<Vec<RepoConflictResolutionClaim>> {
        let mut claims = Vec::new();
        for claim_id in self.claims_for_subject(branch_subject)? {
            let Some(body) = self.get_claim(&claim_id)? else {
                continue;
            };
            if body.predicate != PREDICATE_CONFLICT_RESOLVED
                || body.subject != ClaimSubject::Entity(*branch_subject)
            {
                continue;
            }
            let Ok(value) = decode_repo_conflict_resolution_value(&body.value) else {
                continue;
            };
            claims.push(RepoConflictResolutionClaim {
                claim_id,
                subject: *branch_subject,
                repo_ref: value.repo_ref,
                branch: value.branch,
                open_conflict_claim_id: value.open_conflict_claim_id,
                resolved_tree: value.resolved_tree,
                resolved_paths: value.resolved_paths,
            });
        }
        claims.sort_by(|left, right| {
            left.branch
                .cmp(&right.branch)
                .then_with(|| left.claim_id.as_bytes().cmp(right.claim_id.as_bytes()))
        });
        Ok(claims)
    }

    fn repo_mutation_oplog_for_canonical(
        &self,
        repo_ref: &RepoRef,
    ) -> Result<Vec<RepoMutationOplogEntry>> {
        let repo_key_hash = repo_mutation_repo_key_hash(repo_ref);
        let prefix = repo_mutation_oplog_prefix(&repo_key_hash);
        let rtxn = self.store.env.read_txn()?;
        let mut entries = Vec::new();
        for row in self.store.vault_meta.prefix_iter(&rtxn, &prefix)? {
            let (_, bytes) = row?;
            entries.push(decode_oplog_entry(bytes)?);
        }
        entries.sort_by_key(|entry| entry.seq);
        Ok(entries)
    }

    fn recover_prepared_repo_mutations_locked(
        &self,
        repo_ref: &RepoRef,
        repo_root: &Path,
    ) -> Result<Vec<RepoMutationOutcome>> {
        let prepared_entries = self
            .repo_mutation_oplog_for_canonical(repo_ref)?
            .into_iter()
            .filter(|entry| entry.status == RepoMutationStatus::Prepared)
            .collect::<Vec<_>>();
        let mut outcomes = Vec::new();
        for stale in prepared_entries {
            let request = RepoMutationRequest {
                repo_ref: repo_ref.clone(),
                actor_id: stale.actor_id,
                session_id: stale.session_id,
                operation: RepoMutationOperation::RecoverSnapshot {
                    fork_hash: stale.pre_action_fork_hash,
                },
            };
            let recovery = self.prepare_repo_mutation(repo_ref, &request, repo_root)?;
            match execute_repo_mutation(self, repo_ref, repo_root, &request.operation) {
                Ok(_) => {
                    let entry = self.finish_repo_mutation(
                        &recovery,
                        RepoMutationStatus::Applied,
                        None,
                        now_millis(),
                    )?;
                    self.finish_repo_mutation(
                        &PreparedRepoMutation {
                            repo_key_hash: repo_mutation_repo_key_hash(repo_ref),
                            seq: stale.seq,
                        },
                        RepoMutationStatus::Failed,
                        Some("auto-recovered pre-action forkHash after incomplete mutation".into()),
                        now_millis(),
                    )?;
                    outcomes.push(RepoMutationOutcome {
                        entry,
                        repo_conflict_claim_id: None,
                    });
                }
                Err(error) => {
                    let failure = truncate_failure(&error.to_string());
                    let _ = self.finish_repo_mutation(
                        &recovery,
                        RepoMutationStatus::Failed,
                        Some(failure),
                        now_millis(),
                    );
                    return Err(error);
                }
            }
        }
        Ok(outcomes)
    }

    fn prepare_repo_mutation(
        &self,
        repo_ref: &RepoRef,
        request: &RepoMutationRequest,
        repo_root: &Path,
    ) -> Result<PreparedRepoMutation> {
        let (fork_hash, snapshot_bytes) = capture_repo_snapshot(repo_root)?;
        let repo_key_hash = repo_mutation_repo_key_hash(repo_ref);
        let started_at_ms = now_millis();
        let mut wtxn = self.store.env.write_txn()?;
        store_snapshot_if_absent(self, &mut wtxn, fork_hash, &snapshot_bytes)?;
        let seq = allocate_next_repo_mutation_seq(self, &mut wtxn, &repo_key_hash)?;
        let stored = StoredRepoMutationOplogEntry {
            schema_version: REPO_MUTATION_OPLOG_SCHEMA_VERSION,
            repo_ref: repo_ref.canonical(),
            seq,
            operation_kind: request.operation.kind().to_owned(),
            operation_subject: Some(operation_subject(&request.operation)),
            actor_id: request.actor_id.map(|id| *id.as_bytes()),
            session_id: request.session_id.map(|id| *id.as_bytes()),
            started_at_ms,
            finished_at_ms: None,
            pre_action_fork_hash: fork_hash,
            status: RepoMutationStatus::Prepared.as_str().to_owned(),
            failure: None,
        };
        let encoded = encode_oplog_entry(&stored)?;
        self.store.vault_meta.put(
            &mut wtxn,
            &repo_mutation_oplog_key(&repo_key_hash, seq),
            &encoded,
        )?;
        wtxn.commit()?;
        Ok(PreparedRepoMutation { repo_key_hash, seq })
    }

    fn finish_repo_mutation(
        &self,
        prepared: &PreparedRepoMutation,
        status: RepoMutationStatus,
        failure: Option<String>,
        finished_at_ms: u64,
    ) -> Result<RepoMutationOplogEntry> {
        let key = repo_mutation_oplog_key(&prepared.repo_key_hash, prepared.seq);
        let mut wtxn = self.store.env.write_txn()?;
        let raw =
            self.store
                .vault_meta
                .get(&wtxn, &key)?
                .ok_or(Error::InvalidRepoMutationRecord(
                    "repo mutation oplog row disappeared before completion",
                ))?;
        let mut stored = decode_stored_oplog_entry(raw)?;
        stored.status = status.as_str().to_owned();
        stored.failure = failure;
        stored.finished_at_ms = Some(finished_at_ms);
        let encoded = encode_oplog_entry(&stored)?;
        self.store.vault_meta.put(&mut wtxn, &key, &encoded)?;
        wtxn.commit()?;
        public_oplog_entry(stored)
    }
}

fn execute_repo_mutation(
    vault: &Vault,
    repo_ref: &RepoRef,
    repo_root: &Path,
    operation: &RepoMutationOperation,
) -> Result<Option<EntityId>> {
    match operation {
        RepoMutationOperation::CommitFile {
            path,
            content,
            message,
        } => {
            validate_relative_repo_path(path)?;
            validate_commit_message(message)?;
            commit_file_through_queue_worktree(repo_root, path, content, message)?;
            Ok(None)
        }
        RepoMutationOperation::CreateWorktree {
            worktree_path,
            base_ref,
        } => {
            validate_worktree_path(worktree_path)?;
            validate_base_ref(base_ref)?;
            run_git(
                repo_root,
                &[
                    "worktree".to_owned(),
                    "add".to_owned(),
                    "--detach".to_owned(),
                    "--".to_owned(),
                    path_arg(worktree_path)?,
                    base_ref.clone(),
                ],
            )?;
            Ok(None)
        }
        RepoMutationOperation::RecordConflict {
            branch_subject,
            branch_name,
            ours_ref,
            theirs_ref,
        } => {
            let claim_id = record_repo_conflict(
                vault,
                repo_ref,
                repo_root,
                *branch_subject,
                branch_name,
                ours_ref,
                theirs_ref,
            )?;
            Ok(Some(claim_id))
        }
        RepoMutationOperation::RemoveWorktree { worktree_path } => {
            validate_worktree_path(worktree_path)?;
            run_git(
                repo_root,
                &[
                    "worktree".to_owned(),
                    "remove".to_owned(),
                    "--force".to_owned(),
                    "--".to_owned(),
                    path_arg(worktree_path)?,
                ],
            )?;
            Ok(None)
        }
        RepoMutationOperation::RecoverSnapshot { fork_hash } => {
            restore_repo_snapshot(vault, repo_ref, repo_root, *fork_hash)?;
            Ok(None)
        }
        RepoMutationOperation::ResolveConflictFile {
            branch_subject,
            open_conflict_claim_id,
            branch_name,
            path,
            content,
            message,
        } => {
            let claim_id = resolve_repo_conflict_file(
                vault,
                repo_ref,
                repo_root,
                *branch_subject,
                *open_conflict_claim_id,
                branch_name,
                path,
                content,
                message,
            )?;
            Ok(Some(claim_id))
        }
    }
}

fn validate_operation(operation: &RepoMutationOperation) -> Result<()> {
    match operation {
        RepoMutationOperation::CommitFile { path, message, .. } => {
            validate_relative_repo_path(path)?;
            validate_commit_message(message)
        }
        RepoMutationOperation::CreateWorktree {
            worktree_path,
            base_ref,
        } => {
            validate_worktree_path(worktree_path)?;
            validate_base_ref(base_ref)
        }
        RepoMutationOperation::RecordConflict {
            branch_name,
            ours_ref,
            theirs_ref,
            ..
        } => {
            validate_git_ref_label(branch_name)?;
            validate_base_ref(ours_ref)?;
            validate_base_ref(theirs_ref)
        }
        RepoMutationOperation::RemoveWorktree { worktree_path } => {
            validate_worktree_path(worktree_path)
        }
        RepoMutationOperation::RecoverSnapshot { .. } => Ok(()),
        RepoMutationOperation::ResolveConflictFile {
            branch_name,
            path,
            message,
            ..
        } => {
            validate_git_ref_label(branch_name)?;
            validate_relative_repo_path(path)?;
            validate_commit_message(message)
        }
    }
}

fn record_repo_conflict(
    vault: &Vault,
    repo_ref: &RepoRef,
    repo_root: &Path,
    branch_subject: EntityId,
    branch_name: &str,
    ours_ref: &str,
    theirs_ref: &str,
) -> Result<EntityId> {
    validate_git_ref_label(branch_name)?;
    validate_base_ref(ours_ref)?;
    validate_base_ref(theirs_ref)?;

    let base_commit = merge_base_commit(repo_root, ours_ref, theirs_ref)?;
    let base_tree = tree_hash_for_ref(repo_root, &base_commit)?;
    let ours_tree = tree_hash_for_ref(repo_root, ours_ref)?;
    let theirs_tree = tree_hash_for_ref(repo_root, theirs_ref)?;
    let conflicted_paths = merge_conflicted_paths(
        repo_root,
        &base_commit,
        ours_ref,
        theirs_ref,
        &ours_tree,
        &theirs_tree,
    )?;
    if conflicted_paths.is_empty() {
        return Err(Error::InvalidRepoMutationRecord(
            "repo conflict record requires at least one conflicted path",
        ));
    }

    let claim_id = EntityId::now();
    put_repo_conflict_open_claim(
        vault,
        claim_id,
        branch_subject,
        RepoConflictOpenValue {
            repo_ref: repo_ref.clone(),
            branch: branch_name.to_owned(),
            base_tree,
            ours_tree,
            theirs_tree,
            conflicted_paths,
        },
    )?;
    Ok(claim_id)
}

#[expect(
    clippy::too_many_arguments,
    reason = "operation payload fields stay explicit at the mutation boundary"
)]
fn resolve_repo_conflict_file(
    vault: &Vault,
    repo_ref: &RepoRef,
    repo_root: &Path,
    branch_subject: EntityId,
    open_conflict_claim_id: EntityId,
    branch_name: &str,
    path: &str,
    content: &[u8],
    message: &str,
) -> Result<EntityId> {
    validate_git_ref_label(branch_name)?;
    validate_relative_repo_path(path)?;
    validate_commit_message(message)?;
    let open = require_active_repo_conflict_claim(vault, &open_conflict_claim_id, branch_subject)?;
    if open.repo_ref != *repo_ref || open.branch != branch_name {
        return Err(Error::InvalidRepoMutationRecord(
            "open conflict claim does not match this repo branch",
        ));
    }
    if !open
        .conflicted_paths
        .iter()
        .any(|conflict| conflict == path)
    {
        return Err(Error::InvalidRepoMutationRecord(
            "resolved path must be one of the recorded conflicted paths",
        ));
    }
    let current_branch = current_branch(repo_root)?;
    if current_branch != branch_name {
        return Err(Error::InvalidRepoMutationRecord(
            "repo conflict resolution must run on the recorded branch",
        ));
    }

    commit_file_through_queue_worktree(repo_root, path, content, message)?;
    let resolved_tree = tree_hash_for_ref(repo_root, "HEAD")?;
    let claim_id = EntityId::now();
    put_repo_conflict_resolution_claim(
        vault,
        claim_id,
        branch_subject,
        RepoConflictResolutionValue {
            repo_ref: repo_ref.clone(),
            branch: branch_name.to_owned(),
            open_conflict_claim_id,
            resolved_tree,
            resolved_paths: normalize_repo_conflict_paths(vec![path.to_owned()])?,
        },
    )?;
    supersede_repo_conflict_claim(vault, claim_id, open_conflict_claim_id, now_secs())?;
    Ok(claim_id)
}

fn require_active_repo_conflict_claim(
    vault: &Vault,
    claim_id: &EntityId,
    branch_subject: EntityId,
) -> Result<RepoConflictClaim> {
    let body = vault.get_claim(claim_id)?.ok_or(Error::EntityNotFound)?;
    if body.predicate != PREDICATE_CONFLICT_OPEN
        || body.lifecycle != ClaimLifecycleStatus::Active
        || body.subject != ClaimSubject::Entity(branch_subject)
    {
        return Err(Error::InvalidRepoMutationRecord(
            "open conflict claim must be active and attached to the branch subject",
        ));
    }
    let value = decode_repo_conflict_open_value(&body.value)?;
    Ok(RepoConflictClaim {
        claim_id: *claim_id,
        subject: branch_subject,
        repo_ref: value.repo_ref,
        branch: value.branch,
        base_tree: value.base_tree,
        ours_tree: value.ours_tree,
        theirs_tree: value.theirs_tree,
        conflicted_paths: value.conflicted_paths,
    })
}

fn put_repo_conflict_open_claim(
    vault: &Vault,
    claim_id: EntityId,
    branch_subject: EntityId,
    value: RepoConflictOpenValue,
) -> Result<()> {
    let learned_at = now_secs();
    let body = ClaimBody::new(
        PREDICATE_CONFLICT_OPEN,
        ClaimSubject::Entity(branch_subject),
        encode_repo_conflict_open_value(&value),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    validate_repo_conflict_claim_value(&body.predicate, &body.value)?;
    put_engine_repo_conflict_claim(vault, claim_id, branch_subject, &body, learned_at)
}

fn put_repo_conflict_resolution_claim(
    vault: &Vault,
    claim_id: EntityId,
    branch_subject: EntityId,
    value: RepoConflictResolutionValue,
) -> Result<()> {
    let learned_at = now_secs();
    let body = ClaimBody::new(
        PREDICATE_CONFLICT_RESOLVED,
        ClaimSubject::Entity(branch_subject),
        encode_repo_conflict_resolution_value(&value),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    validate_repo_conflict_claim_value(&body.predicate, &body.value)?;
    put_engine_repo_conflict_claim(vault, claim_id, branch_subject, &body, learned_at)
}

fn put_engine_repo_conflict_claim(
    vault: &Vault,
    claim_id: EntityId,
    branch_subject: EntityId,
    body: &ClaimBody,
    learned_at: u64,
) -> Result<()> {
    let data = encode_claim_body(body)?;
    let mut wtxn = vault.store.env.write_txn()?;
    if vault
        .store
        .entities
        .get(&wtxn, branch_subject.as_bytes())?
        .is_none()
    {
        return Err(Error::EntityNotFound);
    }
    let claim_of_weight = EdgeKind::ClaimOf
        .default_weight()
        .ok_or(Error::InvariantViolation(
            "ClaimOf edge missing default weight",
        ))?;
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        &mut wtxn,
        vec![
            BatchOp::Put {
                id: claim_id,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: true,
            },
            BatchOp::Edge {
                src: claim_id,
                kind: EdgeKind::ClaimOf,
                tgt: branch_subject,
                weight: claim_of_weight,
                vad: Vad::NEUTRAL,
            },
        ],
        vault.text_index_trusted.load(Ordering::Acquire),
        false,
        true,
    )?;
    wtxn.commit()?;
    Ok(())
}

fn supersede_repo_conflict_claim(
    vault: &Vault,
    new_id: EntityId,
    old_id: EntityId,
    now: u64,
) -> Result<()> {
    if new_id == old_id {
        return Err(Error::ClaimSelfSupersession);
    }
    let mut wtxn = vault.store.env.write_txn()?;
    let new_raw = vault
        .store
        .entities
        .get(&wtxn, new_id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let new_header =
        EntityMetadataHeader::parse(new_raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if new_header.entity_type != ENTITY_TYPE_CLAIM {
        return Err(Error::InvalidClaimBody("entity is not a type-0 CLAIM"));
    }
    let new_body = decode_claim_body(&new_raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    if new_body.predicate != PREDICATE_CONFLICT_RESOLVED
        || new_body.lifecycle != ClaimLifecycleStatus::Active
    {
        return Err(Error::InvalidRepoMutationRecord(
            "new repo conflict claim must be an active resolution claim",
        ));
    }

    let old_raw = vault
        .store
        .entities
        .get(&wtxn, old_id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let old_header =
        EntityMetadataHeader::parse(old_raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if old_header.entity_type != ENTITY_TYPE_CLAIM {
        return Err(Error::InvalidClaimBody("entity is not a type-0 CLAIM"));
    }
    let mut old_body = decode_claim_body(&old_raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    if old_body.predicate != PREDICATE_CONFLICT_OPEN {
        return Err(Error::InvalidRepoMutationRecord(
            "old repo conflict claim must be an open conflict claim",
        ));
    }
    if old_body.lifecycle != ClaimLifecycleStatus::Active {
        return Err(Error::ClaimAlreadyClosed {
            status: old_body.lifecycle,
        });
    }
    old_body.lifecycle = ClaimLifecycleStatus::Superseded;
    old_body.valid_to = Some(now);
    let data = encode_claim_body(&old_body)?;
    let supersedes_weight =
        EdgeKind::Supersedes
            .default_weight()
            .ok_or(Error::InvariantViolation(
                "Supersedes edge missing default weight",
            ))?;
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        &mut wtxn,
        vec![
            BatchOp::Put {
                id: old_id,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: TimeRange {
                    start: old_header.occurred_start,
                    end: now,
                },
                learned_at: old_header.learned_at,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: true,
            },
            BatchOp::EdgeWithCreatedAt {
                src: new_id,
                kind: EdgeKind::Supersedes,
                tgt: old_id,
                weight: supersedes_weight,
                created_at: now,
                vad: Vad::NEUTRAL,
                provenance: None,
            },
        ],
        vault.text_index_trusted.load(Ordering::Acquire),
        false,
        true,
    )?;
    wtxn.commit()?;
    Ok(())
}

fn capture_repo_snapshot(repo_root: &Path) -> Result<(RepoForkHash, Vec<u8>)> {
    let head = git_output_optional(
        repo_root,
        &[
            "rev-parse".to_owned(),
            "--verify".to_owned(),
            "HEAD".to_owned(),
        ],
    )?
    .map(|bytes| utf8_trimmed(bytes, "git HEAD must be UTF-8"))
    .transpose()?;
    let mut entries = Vec::new();
    let mut stats = SnapshotStats::default();
    collect_snapshot_entries(repo_root, repo_root, &mut entries, &mut stats)?;
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let snapshot = StoredRepoSnapshot {
        schema_version: REPO_MUTATION_OPLOG_SCHEMA_VERSION,
        head,
        entries,
    };
    let encoded = encode_snapshot(&snapshot)?;
    let hash = sha256_bytes(&encoded);
    Ok((hash, encoded))
}

fn collect_snapshot_entries(
    repo_root: &Path,
    dir: &Path,
    entries: &mut Vec<StoredRepoSnapshotEntry>,
    stats: &mut SnapshotStats,
) -> Result<()> {
    let mut children = fs::read_dir(dir)?.collect::<std::result::Result<Vec<_>, _>>()?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        if child.file_name() == OsStr::new(".git") {
            continue;
        }
        let path = child.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_dir() {
            collect_snapshot_entries(repo_root, &path, entries, stats)?;
            continue;
        }
        let relative = repo_relative_path(repo_root, &path)?;
        if metadata.file_type().is_symlink() {
            let target = fs::read_link(&path)?;
            let target = path_arg(&target)?;
            record_snapshot_entry_size(stats, target.len() as u64)?;
            entries.push(StoredRepoSnapshotEntry {
                path: relative,
                kind: StoredRepoSnapshotEntryKind::Symlink,
                executable: false,
                content: Vec::new(),
                symlink_target: Some(target),
            });
        } else if metadata.file_type().is_file() {
            if metadata.len() > MAX_REPO_MUTATION_SNAPSHOT_FILE_BYTES {
                return Err(Error::InvalidRepoMutationRecord(
                    "repo mutation snapshot file exceeds max bytes",
                ));
            }
            record_snapshot_entry_size(stats, metadata.len())?;
            entries.push(StoredRepoSnapshotEntry {
                path: relative,
                kind: StoredRepoSnapshotEntryKind::File,
                executable: is_executable(&metadata),
                content: fs::read(&path)?,
                symlink_target: None,
            });
        } else {
            return Err(Error::InvalidRepoMutationRecord(
                "repo snapshot supports only files, directories, and symlinks",
            ));
        }
    }
    Ok(())
}

fn restore_repo_snapshot(
    vault: &Vault,
    repo_ref: &RepoRef,
    repo_root: &Path,
    fork_hash: RepoForkHash,
) -> Result<()> {
    if !snapshot_recorded_for_repo(vault, repo_ref, fork_hash)? {
        return Err(Error::InvalidRepoMutationRecord(
            "requested repo snapshot forkHash is not recorded for this repo",
        ));
    }
    let key = repo_mutation_snapshot_key(fork_hash);
    let rtxn = vault.store.env.read_txn()?;
    let raw = vault
        .store
        .vault_meta
        .get(&rtxn, &key)?
        .ok_or(Error::InvalidRepoMutationRecord(
            "requested repo snapshot forkHash is unknown",
        ))?
        .to_vec();
    drop(rtxn);
    if sha256_bytes(&raw) != fork_hash {
        return Err(Error::CorruptedIndex(
            "repo mutation snapshot hash mismatch",
        ));
    }
    let snapshot = decode_snapshot(&raw)?;
    let snapshot_head = snapshot.head.clone();
    let desired: BTreeSet<String> = snapshot
        .entries
        .iter()
        .map(|entry| entry.path.clone())
        .collect();
    let mut current = BTreeSet::new();
    let mut dirs = Vec::new();
    collect_restore_inventory(repo_root, repo_root, &mut current, &mut dirs)?;

    for path in current.difference(&desired) {
        remove_existing_path(&repo_root.join(path))?;
    }
    remove_empty_dirs(dirs)?;

    for entry in snapshot.entries {
        validate_relative_repo_path(&entry.path)?;
        let target = repo_root.join(&entry.path);
        if fs::symlink_metadata(&target).is_ok() {
            remove_existing_path(&target)?;
        }
        match entry.kind {
            StoredRepoSnapshotEntryKind::File => {
                write_repo_file_no_symlink(repo_root, &entry.path, &entry.content)?;
                set_executable(&target, entry.executable)?;
            }
            StoredRepoSnapshotEntryKind::Symlink => {
                let target_path = entry
                    .symlink_target
                    .ok_or(Error::InvalidRepoMutationRecord(
                        "symlink snapshot entry missing target",
                    ))?;
                let target = ensure_repo_parent_dirs_no_symlink(repo_root, &entry.path)?;
                create_symlink(Path::new(&target_path), &target)?;
            }
        }
    }
    if let Some(head) = snapshot_head {
        run_git(
            repo_root,
            &["update-ref".to_owned(), "HEAD".to_owned(), head],
        )?;
        run_git(
            repo_root,
            &[
                "read-tree".to_owned(),
                "--reset".to_owned(),
                "HEAD".to_owned(),
            ],
        )?;
    }
    Ok(())
}

fn record_snapshot_entry_size(stats: &mut SnapshotStats, bytes: u64) -> Result<()> {
    stats.files = stats
        .files
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("repo_mutation_snapshot_files"))?;
    if stats.files > MAX_REPO_MUTATION_SNAPSHOT_FILES {
        return Err(Error::InvalidRepoMutationRecord(
            "repo mutation snapshot exceeds max file count",
        ));
    }
    stats.total_bytes = stats
        .total_bytes
        .checked_add(bytes)
        .ok_or(Error::ArithmeticOverflow("repo_mutation_snapshot_bytes"))?;
    if stats.total_bytes > MAX_REPO_MUTATION_SNAPSHOT_TOTAL_BYTES {
        return Err(Error::InvalidRepoMutationRecord(
            "repo mutation snapshot exceeds max total bytes",
        ));
    }
    Ok(())
}

fn snapshot_recorded_for_repo(
    vault: &Vault,
    repo_ref: &RepoRef,
    fork_hash: RepoForkHash,
) -> Result<bool> {
    Ok(vault
        .repo_mutation_oplog_for_canonical(repo_ref)?
        .iter()
        .any(|entry| entry.pre_action_fork_hash == fork_hash))
}

fn commit_file_through_queue_worktree(
    repo_root: &Path,
    path: &str,
    content: &[u8],
    message: &str,
) -> Result<()> {
    let base_head = utf8_trimmed(
        run_git(
            repo_root,
            &[
                "rev-parse".to_owned(),
                "--verify".to_owned(),
                "HEAD".to_owned(),
            ],
        )?,
        "git HEAD must be UTF-8",
    )?;
    let worktree_path = create_queue_worktree(repo_root)?;
    let mutation = (|| -> Result<()> {
        write_repo_file_no_symlink(&worktree_path, path, content)?;
        run_git(
            &worktree_path,
            &["add".to_owned(), "--".to_owned(), path.to_owned()],
        )?;
        run_git(
            &worktree_path,
            &[
                "-c".to_owned(),
                "user.name=Oneiron".to_owned(),
                "-c".to_owned(),
                "user.email=oneiron@example.invalid".to_owned(),
                "commit".to_owned(),
                "-m".to_owned(),
                message.to_owned(),
                "--only".to_owned(),
                "--".to_owned(),
                path.to_owned(),
            ],
        )?;
        let new_head = utf8_trimmed(
            run_git(
                &worktree_path,
                &[
                    "rev-parse".to_owned(),
                    "--verify".to_owned(),
                    "HEAD".to_owned(),
                ],
            )?,
            "git HEAD must be UTF-8",
        )?;
        write_repo_file_no_symlink(repo_root, path, content)?;
        run_git(
            repo_root,
            &[
                "update-ref".to_owned(),
                "HEAD".to_owned(),
                new_head,
                base_head,
            ],
        )?;
        run_git(
            repo_root,
            &["add".to_owned(), "--".to_owned(), path.to_owned()],
        )?;
        Ok(())
    })();
    let cleanup = remove_queue_worktree(repo_root, &worktree_path);
    match (mutation, cleanup) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn merge_base_commit(repo_root: &Path, ours_ref: &str, theirs_ref: &str) -> Result<String> {
    let base = utf8_trimmed(
        run_git(
            repo_root,
            &[
                "merge-base".to_owned(),
                ours_ref.to_owned(),
                theirs_ref.to_owned(),
            ],
        )?,
        "git merge-base must be UTF-8",
    )?;
    validate_git_object_hash(&base, "merge-base must be a 40-hex commit")?;
    Ok(base)
}

fn tree_hash_for_ref(repo_root: &Path, git_ref: &str) -> Result<String> {
    let tree_ref = format!("{git_ref}^{{tree}}");
    let tree = utf8_trimmed(
        run_git(
            repo_root,
            &["rev-parse".to_owned(), "--verify".to_owned(), tree_ref],
        )?,
        "git tree hash must be UTF-8",
    )?;
    validate_git_object_hash(&tree, "tree hash must be a 40-hex object id")?;
    Ok(tree)
}

fn current_branch(repo_root: &Path) -> Result<String> {
    let branch = utf8_trimmed(
        run_git(
            repo_root,
            &["branch".to_owned(), "--show-current".to_owned()],
        )?,
        "git branch name must be UTF-8",
    )?;
    validate_git_ref_label(&branch)?;
    Ok(branch)
}

fn merge_conflicted_paths(
    repo_root: &Path,
    base_commit: &str,
    ours_ref: &str,
    theirs_ref: &str,
    ours_tree: &str,
    theirs_tree: &str,
) -> Result<Vec<String>> {
    let output = run_git_allow_exit_codes(
        repo_root,
        &[
            "merge-tree".to_owned(),
            "--write-tree".to_owned(),
            "--name-only".to_owned(),
            "--no-messages".to_owned(),
            "-z".to_owned(),
            "--merge-base".to_owned(),
            base_commit.to_owned(),
            ours_ref.to_owned(),
            theirs_ref.to_owned(),
        ],
        &[0, 1],
    )?;

    let mut paths = Vec::new();
    for token in output.split(|byte| *byte == 0) {
        if token.is_empty() {
            continue;
        }
        let Ok(path) = std::str::from_utf8(token) else {
            continue;
        };
        if validate_relative_repo_path(path).is_err() {
            continue;
        }
        if path_exists_in_tree(repo_root, ours_tree, path)?
            || path_exists_in_tree(repo_root, theirs_tree, path)?
        {
            paths.push(path.to_owned());
        }
    }
    normalize_repo_conflict_paths(paths)
}

fn path_exists_in_tree(repo_root: &Path, tree_hash: &str, path: &str) -> Result<bool> {
    validate_git_object_hash(tree_hash, "tree hash must be a 40-hex object id")?;
    validate_relative_repo_path(path)?;
    let spec = format!("{tree_hash}:{path}");
    git_status_success(repo_root, &["cat-file".to_owned(), "-e".to_owned(), spec])
}

fn normalize_repo_conflict_paths(paths: Vec<String>) -> Result<Vec<String>> {
    let mut normalized = BTreeSet::new();
    for path in paths {
        validate_relative_repo_path(&path)?;
        normalized.insert(path);
        if normalized.len() > MAX_REPO_CONFLICT_PATHS {
            return Err(Error::InvalidRepoMutationRecord(
                "repo conflict path list exceeds max count",
            ));
        }
    }
    Ok(normalized.into_iter().collect())
}

fn encode_repo_conflict_open_value(value: &RepoConflictOpenValue) -> Value {
    Value::Map(vec![
        (
            Value::from(REPO_CONFLICT_OPEN_VALUE_KEYS[0]),
            Value::from(u64::from(REPO_CONFLICT_CLAIM_VALUE_SCHEMA_VERSION)),
        ),
        (
            Value::from(REPO_CONFLICT_OPEN_VALUE_KEYS[1]),
            Value::from(REPO_CONFLICT_KIND_REPO_BRANCH),
        ),
        (
            Value::from(REPO_CONFLICT_OPEN_VALUE_KEYS[2]),
            Value::from(value.repo_ref.canonical()),
        ),
        (
            Value::from(REPO_CONFLICT_OPEN_VALUE_KEYS[3]),
            Value::from(value.branch.clone()),
        ),
        (
            Value::from(REPO_CONFLICT_OPEN_VALUE_KEYS[4]),
            Value::from(value.base_tree.clone()),
        ),
        (
            Value::from(REPO_CONFLICT_OPEN_VALUE_KEYS[5]),
            Value::from(value.ours_tree.clone()),
        ),
        (
            Value::from(REPO_CONFLICT_OPEN_VALUE_KEYS[6]),
            Value::from(value.theirs_tree.clone()),
        ),
        (
            Value::from(REPO_CONFLICT_OPEN_VALUE_KEYS[7]),
            Value::Array(
                value
                    .conflicted_paths
                    .iter()
                    .cloned()
                    .map(Value::from)
                    .collect(),
            ),
        ),
    ])
}

fn encode_repo_conflict_resolution_value(value: &RepoConflictResolutionValue) -> Value {
    Value::Map(vec![
        (
            Value::from(REPO_CONFLICT_RESOLUTION_VALUE_KEYS[0]),
            Value::from(u64::from(REPO_CONFLICT_CLAIM_VALUE_SCHEMA_VERSION)),
        ),
        (
            Value::from(REPO_CONFLICT_RESOLUTION_VALUE_KEYS[1]),
            Value::from(REPO_CONFLICT_KIND_REPO_BRANCH),
        ),
        (
            Value::from(REPO_CONFLICT_RESOLUTION_VALUE_KEYS[2]),
            Value::from(value.repo_ref.canonical()),
        ),
        (
            Value::from(REPO_CONFLICT_RESOLUTION_VALUE_KEYS[3]),
            Value::from(value.branch.clone()),
        ),
        (
            Value::from(REPO_CONFLICT_RESOLUTION_VALUE_KEYS[4]),
            Value::Binary(value.open_conflict_claim_id.as_bytes().to_vec()),
        ),
        (
            Value::from(REPO_CONFLICT_RESOLUTION_VALUE_KEYS[5]),
            Value::from(value.resolved_tree.clone()),
        ),
        (
            Value::from(REPO_CONFLICT_RESOLUTION_VALUE_KEYS[6]),
            Value::Array(
                value
                    .resolved_paths
                    .iter()
                    .cloned()
                    .map(Value::from)
                    .collect(),
            ),
        ),
    ])
}

pub(crate) fn validate_repo_conflict_claim_value(predicate: &str, value: &Value) -> Result<()> {
    match predicate {
        PREDICATE_CONFLICT_OPEN => decode_repo_conflict_open_value(value).map(|_| ()),
        PREDICATE_CONFLICT_RESOLVED => decode_repo_conflict_resolution_value(value).map(|_| ()),
        _ => Ok(()),
    }
}

fn decode_repo_conflict_open_value(value: &Value) -> Result<RepoConflictOpenValue> {
    let map = collect_value_map(value, &REPO_CONFLICT_OPEN_VALUE_KEYS)?;
    validate_schema_version(&map)?;
    validate_kind(&map)?;
    let repo_ref = RepoRef::parse(string_field(
        &map,
        REPO_CONFLICT_OPEN_VALUE_KEYS[2],
        "repo conflict repo_ref must be a string",
    )?)?;
    let branch = string_field_owned(
        &map,
        REPO_CONFLICT_OPEN_VALUE_KEYS[3],
        "repo conflict branch must be a string",
    )?;
    validate_git_ref_label(&branch)?;
    let base_tree = hash_field(&map, REPO_CONFLICT_OPEN_VALUE_KEYS[4])?;
    let ours_tree = hash_field(&map, REPO_CONFLICT_OPEN_VALUE_KEYS[5])?;
    let theirs_tree = hash_field(&map, REPO_CONFLICT_OPEN_VALUE_KEYS[6])?;
    let conflicted_paths = string_array_field(&map, REPO_CONFLICT_OPEN_VALUE_KEYS[7])?;
    if conflicted_paths.is_empty() {
        return Err(Error::InvalidClaimBody(
            "repo conflict claim requires at least one conflicted path",
        ));
    }
    Ok(RepoConflictOpenValue {
        repo_ref,
        branch,
        base_tree,
        ours_tree,
        theirs_tree,
        conflicted_paths,
    })
}

fn decode_repo_conflict_resolution_value(value: &Value) -> Result<RepoConflictResolutionValue> {
    let map = collect_value_map(value, &REPO_CONFLICT_RESOLUTION_VALUE_KEYS)?;
    validate_schema_version(&map)?;
    validate_kind(&map)?;
    let repo_ref = RepoRef::parse(string_field(
        &map,
        REPO_CONFLICT_RESOLUTION_VALUE_KEYS[2],
        "repo conflict resolution repo_ref must be a string",
    )?)?;
    let branch = string_field_owned(
        &map,
        REPO_CONFLICT_RESOLUTION_VALUE_KEYS[3],
        "repo conflict resolution branch must be a string",
    )?;
    validate_git_ref_label(&branch)?;
    let open_conflict_claim_id = entity_id_field(&map, REPO_CONFLICT_RESOLUTION_VALUE_KEYS[4])?;
    let resolved_tree = hash_field(&map, REPO_CONFLICT_RESOLUTION_VALUE_KEYS[5])?;
    let resolved_paths = string_array_field(&map, REPO_CONFLICT_RESOLUTION_VALUE_KEYS[6])?;
    if resolved_paths.is_empty() {
        return Err(Error::InvalidClaimBody(
            "repo conflict resolution requires at least one resolved path",
        ));
    }
    Ok(RepoConflictResolutionValue {
        repo_ref,
        branch,
        open_conflict_claim_id,
        resolved_tree,
        resolved_paths,
    })
}

fn collect_value_map<'a>(
    value: &'a Value,
    expected_keys: &[&str],
) -> Result<HashMap<&'a str, &'a Value>> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidClaimBody(
            "repo conflict claim value must be a map",
        ));
    };
    if entries.len() != expected_keys.len() {
        return Err(Error::InvalidClaimBody(
            "repo conflict claim value keys must match the pinned schema",
        ));
    }

    let mut map = HashMap::with_capacity(entries.len());
    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidClaimBody(
                "repo conflict claim value keys must be strings",
            ));
        };
        if !expected_keys.contains(&key) {
            return Err(Error::InvalidClaimBody(
                "repo conflict claim value contains an unknown key",
            ));
        }
        if map.insert(key, value).is_some() {
            return Err(Error::InvalidClaimBody(
                "repo conflict claim value contains a duplicate key",
            ));
        }
    }
    for expected in expected_keys {
        if !map.contains_key(expected) {
            return Err(Error::InvalidClaimBody(
                "repo conflict claim value is missing a required key",
            ));
        }
    }
    Ok(map)
}

fn validate_schema_version(map: &HashMap<&str, &Value>) -> Result<()> {
    let raw = map
        .get("schema_version")
        .and_then(|value| value.as_u64())
        .ok_or(Error::InvalidClaimBody(
            "repo conflict schema_version must be an integer",
        ))?;
    if raw == u64::from(REPO_CONFLICT_CLAIM_VALUE_SCHEMA_VERSION) {
        Ok(())
    } else {
        Err(Error::InvalidClaimBody(
            "unsupported repo conflict claim schema_version",
        ))
    }
}

fn validate_kind(map: &HashMap<&str, &Value>) -> Result<()> {
    let kind = string_field(map, "kind", "repo conflict kind must be repo_branch")?;
    if kind == REPO_CONFLICT_KIND_REPO_BRANCH {
        Ok(())
    } else {
        Err(Error::InvalidClaimBody(
            "repo conflict kind must be repo_branch",
        ))
    }
}

fn string_field<'a>(
    map: &'a HashMap<&str, &Value>,
    key: &str,
    context: &'static str,
) -> Result<&'a str> {
    map.get(key)
        .and_then(|value| value.as_str())
        .ok_or(Error::InvalidClaimBody(context))
}

fn string_field_owned(
    map: &HashMap<&str, &Value>,
    key: &str,
    context: &'static str,
) -> Result<String> {
    Ok(string_field(map, key, context)?.to_owned())
}

fn hash_field(map: &HashMap<&str, &Value>, key: &str) -> Result<String> {
    let hash = string_field(map, key, "repo conflict tree hash must be a string")?.to_owned();
    validate_git_object_hash(&hash, "repo conflict tree hash must be a 40-hex object id")?;
    Ok(hash)
}

fn entity_id_field(map: &HashMap<&str, &Value>, key: &str) -> Result<EntityId> {
    let Value::Binary(bytes) = map
        .get(key)
        .ok_or(Error::InvalidClaimBody("repo conflict entity id missing"))?
    else {
        return Err(Error::InvalidClaimBody(
            "repo conflict entity id must be binary",
        ));
    };
    let raw: [u8; 16] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidClaimBody("repo conflict entity id must be 16 bytes"))?;
    EntityId::from_bytes(raw).map_err(|_| Error::InvalidClaimBody("invalid entity id"))
}

fn string_array_field(map: &HashMap<&str, &Value>, key: &str) -> Result<Vec<String>> {
    let Value::Array(values) = map
        .get(key)
        .ok_or(Error::InvalidClaimBody("repo conflict path array missing"))?
    else {
        return Err(Error::InvalidClaimBody(
            "repo conflict paths must be an array",
        ));
    };
    let mut paths = Vec::with_capacity(values.len());
    for value in values {
        let Some(path) = value.as_str() else {
            return Err(Error::InvalidClaimBody(
                "repo conflict paths must be strings",
            ));
        };
        paths.push(path.to_owned());
    }
    normalize_repo_conflict_paths(paths).map_err(|error| match error {
        Error::InvalidRepoMutationRecord(_) => {
            Error::InvalidClaimBody("repo conflict path is invalid")
        }
        other => other,
    })
}

fn create_queue_worktree(repo_root: &Path) -> Result<PathBuf> {
    let worktree_path = queue_owned_worktree_path(repo_root)?;
    run_git(
        repo_root,
        &[
            "worktree".to_owned(),
            "add".to_owned(),
            "--detach".to_owned(),
            "--".to_owned(),
            path_arg(&worktree_path)?,
            "HEAD".to_owned(),
        ],
    )?;
    Ok(worktree_path)
}

fn remove_queue_worktree(repo_root: &Path, worktree_path: &Path) -> Result<()> {
    let result = run_git(
        repo_root,
        &[
            "worktree".to_owned(),
            "remove".to_owned(),
            "--force".to_owned(),
            "--".to_owned(),
            path_arg(worktree_path)?,
        ],
    );
    if worktree_path.exists() {
        let _ = fs::remove_dir_all(worktree_path);
    }
    result.map(|_| ())
}

fn queue_owned_worktree_path(repo_root: &Path) -> Result<PathBuf> {
    let common_dir = git_common_dir(repo_root)?;
    for _ in 0..16 {
        let counter = REPO_MUTATION_WORKTREE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let seed = format!(
            "{}:{}:{}:{}",
            common_dir.display(),
            std::process::id(),
            now_millis(),
            counter
        );
        let suffix = &hex_bytes(&sha256_bytes(seed.as_bytes()))[..24];
        let path = std::env::temp_dir().join(format!("oneiron-repo-mutation-{suffix}"));
        if !path.exists() {
            return Ok(path);
        }
    }
    Err(Error::InvalidRepoMutationRecord(
        "unable to allocate queue-owned worktree path",
    ))
}

fn write_repo_file_no_symlink(repo_root: &Path, path: &str, content: &[u8]) -> Result<()> {
    let target = safe_repo_file_target(repo_root, path)?;
    write_file_no_follow(&target, content)
}

fn safe_repo_file_target(repo_root: &Path, path: &str) -> Result<PathBuf> {
    let target = ensure_repo_parent_dirs_no_symlink(repo_root, path)?;
    match fs::symlink_metadata(&target) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(Error::InvalidRepoMutationRecord(
            "repo mutation path must not traverse symlinks",
        )),
        Ok(metadata) if metadata.file_type().is_file() => Ok(target),
        Ok(_) => Err(Error::InvalidRepoMutationRecord(
            "repo mutation target must be a regular file or absent",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(target),
        Err(error) => Err(error.into()),
    }
}

fn ensure_repo_parent_dirs_no_symlink(repo_root: &Path, path: &str) -> Result<PathBuf> {
    validate_relative_repo_path(path)?;
    let mut current = repo_root.to_path_buf();
    let mut components = Path::new(path).components().peekable();
    while let Some(component) = components.next() {
        let Component::Normal(part) = component else {
            return Err(Error::InvalidRepoMutationRecord(
                "repo mutation path must contain only normal components",
            ));
        };
        current.push(part);
        let is_leaf = components.peek().is_none();
        if is_leaf {
            return Ok(current);
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(Error::InvalidRepoMutationRecord(
                    "repo mutation path must not traverse symlinks",
                ));
            }
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => {
                return Err(Error::InvalidRepoMutationRecord(
                    "repo mutation parent path must be a directory",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(current)
}

#[cfg(unix)]
fn write_file_no_follow(path: &Path, content: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(content)?;
    file.flush()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_file_no_follow(path: &Path, content: &[u8]) -> Result<()> {
    fs::write(path, content)?;
    Ok(())
}

fn collect_restore_inventory(
    repo_root: &Path,
    dir: &Path,
    files: &mut BTreeSet<String>,
    dirs: &mut Vec<PathBuf>,
) -> Result<()> {
    let mut children = fs::read_dir(dir)?.collect::<std::result::Result<Vec<_>, _>>()?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        if child.file_name() == OsStr::new(".git") {
            continue;
        }
        let path = child.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_dir() {
            dirs.push(path.clone());
            collect_restore_inventory(repo_root, &path, files, dirs)?;
        } else if metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            files.insert(repo_relative_path(repo_root, &path)?);
        } else {
            return Err(Error::InvalidRepoMutationRecord(
                "repo restore supports only files, directories, and symlinks",
            ));
        }
    }
    Ok(())
}

fn remove_empty_dirs(mut dirs: Vec<PathBuf>) -> Result<()> {
    dirs.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for dir in dirs {
        if fs::read_dir(&dir)?.next().is_none() {
            fs::remove_dir(dir)?;
        }
    }
    Ok(())
}

fn remove_existing_path(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn store_snapshot_if_absent(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    fork_hash: RepoForkHash,
    snapshot_bytes: &[u8],
) -> Result<()> {
    let key = repo_mutation_snapshot_key(fork_hash);
    if vault.store.vault_meta.get(wtxn, &key)?.is_none() {
        vault.store.vault_meta.put(wtxn, &key, snapshot_bytes)?;
    }
    Ok(())
}

fn allocate_next_repo_mutation_seq(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    repo_key_hash: &str,
) -> Result<u64> {
    let key = repo_mutation_seq_key(repo_key_hash);
    let current = match vault.store.vault_meta.get(wtxn, &key)? {
        Some(bytes) => {
            let bytes: [u8; 8] = bytes.try_into().map_err(|_| {
                Error::InvalidRepoMutationRecord("repo mutation seq row must be 8 bytes")
            })?;
            u64::from_be_bytes(bytes)
        }
        None => 0,
    };
    let next = current
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("repo_mutation_seq"))?;
    vault
        .store
        .vault_meta
        .put(wtxn, &key, &next.to_be_bytes())?;
    Ok(next)
}

fn decode_oplog_entry(bytes: &[u8]) -> Result<RepoMutationOplogEntry> {
    public_oplog_entry(decode_stored_oplog_entry(bytes)?)
}

fn public_oplog_entry(stored: StoredRepoMutationOplogEntry) -> Result<RepoMutationOplogEntry> {
    if stored.schema_version != REPO_MUTATION_OPLOG_SCHEMA_VERSION {
        return Err(Error::InvalidRepoMutationRecord(
            "unsupported repo mutation oplog schema version",
        ));
    }
    let repo_ref = RepoRef::parse(&stored.repo_ref)?;
    Ok(RepoMutationOplogEntry {
        repo_ref,
        seq: stored.seq,
        operation_kind: stored.operation_kind,
        operation_subject: stored.operation_subject,
        actor_id: stored
            .actor_id
            .map(EntityId::from_bytes)
            .transpose()
            .map_err(|_| Error::InvalidRepoMutationRecord("invalid repo mutation actor id"))?,
        session_id: stored
            .session_id
            .map(EntityId::from_bytes)
            .transpose()
            .map_err(|_| Error::InvalidRepoMutationRecord("invalid repo mutation session id"))?,
        started_at_ms: stored.started_at_ms,
        finished_at_ms: stored.finished_at_ms,
        pre_action_fork_hash: stored.pre_action_fork_hash,
        status: RepoMutationStatus::parse(&stored.status)?,
        failure: stored.failure,
    })
}

fn encode_oplog_entry(entry: &StoredRepoMutationOplogEntry) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(entry)
        .map_err(|_| Error::InvariantViolation("repo mutation oplog encode failed"))
}

fn decode_stored_oplog_entry(bytes: &[u8]) -> Result<StoredRepoMutationOplogEntry> {
    rmp_serde::from_slice(bytes)
        .map_err(|_| Error::InvalidRepoMutationRecord("repo mutation oplog is not MessagePack"))
}

fn encode_snapshot(snapshot: &StoredRepoSnapshot) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(snapshot)
        .map_err(|_| Error::InvariantViolation("repo mutation snapshot encode failed"))
}

fn decode_snapshot(bytes: &[u8]) -> Result<StoredRepoSnapshot> {
    let snapshot: StoredRepoSnapshot = rmp_serde::from_slice(bytes).map_err(|_| {
        Error::InvalidRepoMutationRecord("repo mutation snapshot is not MessagePack")
    })?;
    if snapshot.schema_version != REPO_MUTATION_OPLOG_SCHEMA_VERSION {
        return Err(Error::InvalidRepoMutationRecord(
            "unsupported repo mutation snapshot schema version",
        ));
    }
    Ok(snapshot)
}

fn repo_mutation_lock(repo_key: &str) -> Result<Arc<Mutex<()>>> {
    let mut locks = REPO_MUTATION_LOCKS
        .lock()
        .map_err(|_| Error::ConcurrentWrite("repo mutation lock map poisoned"))?;
    Ok(locks
        .entry(repo_key.to_owned())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone())
}

#[cfg(unix)]
fn repo_mutation_file_lock(git_common_dir: &Path) -> Result<RepoMutationFileLock> {
    let lock_path = git_common_dir.join(REPO_MUTATION_LOCK_FILE_NAME);
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)?;
    // SAFETY: `file.as_raw_fd()` is valid for the duration of this call, and
    // `flock(LOCK_EX)` blocks until the kernel grants the advisory lock.
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if result == 0 {
        Ok(RepoMutationFileLock { file })
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

#[cfg(not(unix))]
fn repo_mutation_file_lock(_git_common_dir: &Path) -> Result<RepoMutationFileLock> {
    Ok(RepoMutationFileLock)
}

fn repo_lock_key(git_common_dir: &Path) -> Result<String> {
    git_common_dir
        .to_str()
        .map(str::to_owned)
        .ok_or(Error::InvalidRepoMutationRecord(
            "git common dir must be UTF-8",
        ))
}

fn git_common_dir(repo_root: &Path) -> Result<PathBuf> {
    let output = run_git(
        repo_root,
        &["rev-parse".to_owned(), "--git-common-dir".to_owned()],
    )?;
    let path = PathBuf::from(utf8_trimmed(output, "git common dir must be UTF-8")?);
    let path = if path.is_absolute() {
        path
    } else {
        repo_root.join(path)
    };
    Ok(path.canonicalize()?)
}

fn resolve_mutable_repo_root(repo_ref: &RepoRef) -> Result<PathBuf> {
    let RepoRef::LocalFolder { path, .. } = repo_ref else {
        return Err(Error::InvalidRepoMutationRecord(
            "only local repo_refs can be mutated",
        ));
    };
    let output = run_git_at_path(
        Path::new(path),
        &["rev-parse".to_owned(), "--show-toplevel".to_owned()],
    )?;
    let root = utf8_trimmed(output, "git repo root must be UTF-8")?;
    Ok(PathBuf::from(root).canonicalize()?)
}

fn canonical_repo_ref_for_root(repo_ref: &RepoRef, repo_root: &Path) -> Result<RepoRef> {
    let RepoRef::LocalFolder { commit, .. } = repo_ref else {
        return Err(Error::InvalidRepoMutationRecord(
            "only local repo_refs can be mutated",
        ));
    };
    let path = repo_root
        .to_str()
        .ok_or(Error::InvalidRepoMutationRecord(
            "local repo path must be UTF-8",
        ))?
        .to_owned();
    Ok(RepoRef::LocalFolder {
        path,
        commit: commit.clone(),
    })
}

#[cfg(test)]
fn current_head_commit(repo_root: &Path) -> Result<String> {
    let output = run_git(
        repo_root,
        &[
            "rev-parse".to_owned(),
            "--verify".to_owned(),
            "HEAD".to_owned(),
        ],
    )?;
    let commit = utf8_trimmed(output, "git HEAD commit must be UTF-8")?;
    if commit.len() != CODEBASE_COMMIT_HASH_HEX_LEN
        || !commit.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(Error::InvalidRepoMutationRecord(
            "git HEAD commit must be a 40-hex hash",
        ));
    }
    Ok(commit.to_ascii_lowercase())
}

fn validate_relative_repo_path(path: &str) -> Result<()> {
    if path.is_empty() || path.len() > CODEBASE_FILE_PATH_MAX_BYTES {
        return Err(Error::InvalidRepoMutationRecord(
            "repo mutation path must be non-empty and at most 4096 bytes",
        ));
    }
    if path.contains('\\') {
        return Err(Error::InvalidRepoMutationRecord(
            "repo mutation path must use forward slashes",
        ));
    }
    let parsed = Path::new(path);
    if parsed.is_absolute() {
        return Err(Error::InvalidRepoMutationRecord(
            "repo mutation path must be repository-relative",
        ));
    }
    let mut has_component = false;
    for component in parsed.components() {
        match component {
            Component::Normal(part) => {
                if part == OsStr::new(".git") {
                    return Err(Error::InvalidRepoMutationRecord(
                        "repo mutation path must not target .git",
                    ));
                }
                has_component = true;
            }
            _ => {
                return Err(Error::InvalidRepoMutationRecord(
                    "repo mutation path must not contain . or .. components",
                ));
            }
        }
    }
    if !has_component {
        return Err(Error::InvalidRepoMutationRecord(
            "repo mutation path must contain a file component",
        ));
    }
    Ok(())
}

fn validate_commit_message(message: &str) -> Result<()> {
    if message.is_empty() || message.len() > MAX_COMMIT_MESSAGE_BYTES || message.contains('\0') {
        return Err(Error::InvalidRepoMutationRecord(
            "commit message must be non-empty, bounded, and contain no NUL",
        ));
    }
    Ok(())
}

fn validate_base_ref(base_ref: &str) -> Result<()> {
    if base_ref.is_empty()
        || base_ref.len() > MAX_BASE_REF_BYTES
        || base_ref.contains('\0')
        || base_ref.starts_with('-')
    {
        return Err(Error::InvalidRepoMutationRecord(
            "worktree base ref must be non-empty, bounded, contain no NUL, and not start with '-'",
        ));
    }
    Ok(())
}

fn validate_git_ref_label(label: &str) -> Result<()> {
    validate_base_ref(label)?;
    if label.starts_with('/')
        || label.ends_with('/')
        || label.contains("//")
        || label.contains("..")
        || label.contains("@{")
        || label.ends_with(".lock")
        || label.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(Error::InvalidRepoMutationRecord(
            "git ref label must be a safe branch/ref label",
        ));
    }
    for part in label.split('/') {
        if part.is_empty() || part == "." || part.ends_with(".lock") {
            return Err(Error::InvalidRepoMutationRecord(
                "git ref label must be a safe branch/ref label",
            ));
        }
    }
    Ok(())
}

fn validate_git_object_hash(hash: &str, context: &'static str) -> Result<()> {
    if hash.len() != CODEBASE_COMMIT_HASH_HEX_LEN
        || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(Error::InvalidRepoMutationRecord(context));
    }
    Ok(())
}

fn validate_worktree_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Err(Error::InvalidRepoMutationRecord(
            "worktree path must be non-empty",
        ));
    }
    path_arg(path)?;
    Ok(())
}

fn operation_subject(operation: &RepoMutationOperation) -> String {
    match operation {
        RepoMutationOperation::CommitFile { path, .. } => path.clone(),
        RepoMutationOperation::CreateWorktree { worktree_path, .. }
        | RepoMutationOperation::RemoveWorktree { worktree_path } => {
            worktree_path.to_string_lossy().into_owned()
        }
        RepoMutationOperation::RecordConflict {
            branch_name,
            ours_ref,
            theirs_ref,
            ..
        } => format!("{branch_name}:{ours_ref}..{theirs_ref}"),
        RepoMutationOperation::RecoverSnapshot { fork_hash } => hex_bytes(fork_hash),
        RepoMutationOperation::ResolveConflictFile { path, .. } => path.clone(),
    }
}

fn repo_relative_path(repo_root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(repo_root)
        .map_err(|_| Error::InvariantViolation("repo path escaped root"))?;
    let mut out = String::new();
    for component in relative.components() {
        let Component::Normal(part) = component else {
            return Err(Error::InvalidRepoMutationRecord(
                "repo snapshot path must be normal",
            ));
        };
        let part = part.to_str().ok_or(Error::InvalidRepoMutationRecord(
            "repo snapshot path must be UTF-8",
        ))?;
        if !out.is_empty() {
            out.push('/');
        }
        out.push_str(part);
    }
    validate_relative_repo_path(&out)?;
    Ok(out)
}

fn run_git(repo_root: &Path, args: &[String]) -> Result<Vec<u8>> {
    run_git_at_path(repo_root, args)
}

fn git_status_success(path: &Path, args: &[String]) -> Result<bool> {
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(args)
        .output()?;
    Ok(output.status.success())
}

fn run_git_allow_exit_codes(
    path: &Path,
    args: &[String],
    allowed_codes: &[i32],
) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(args)
        .output()?;
    if output
        .status
        .code()
        .is_some_and(|code| allowed_codes.contains(&code))
    {
        return Ok(output.stdout);
    }
    if output.status.success() && allowed_codes.contains(&0) {
        return Ok(output.stdout);
    }
    Err(Error::InvalidRepoMutationRecord(
        "git command failed with an unexpected exit code",
    ))
}

fn run_git_at_path(path: &Path, args: &[String]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(args)
        .output()?;
    if output.status.success() {
        return Ok(output.stdout);
    }
    Err(Error::RepoMutationFailed(format_git_failure(
        args,
        output.status.code(),
        &output.stderr,
    )))
}

fn git_output_optional(repo_root: &Path, args: &[String]) -> Result<Option<Vec<u8>>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()?;
    if output.status.success() {
        Ok(Some(output.stdout))
    } else {
        Ok(None)
    }
}

fn format_git_failure(args: &[String], code: Option<i32>, stderr: &[u8]) -> String {
    let stderr = String::from_utf8_lossy(stderr);
    let stderr = stderr.trim();
    let message = format!("git {} exited with {:?}: {}", args.join(" "), code, stderr);
    truncate_failure(&message)
}

fn truncate_failure(message: &str) -> String {
    if message.len() <= MAX_REPO_MUTATION_FAILURE_BYTES {
        return message.to_owned();
    }
    let mut end = MAX_REPO_MUTATION_FAILURE_BYTES;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = message[..end].to_owned();
    out.push_str("...");
    out
}

fn path_arg(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or(Error::InvalidRepoMutationRecord("path must be UTF-8"))
}

fn utf8_trimmed(bytes: Vec<u8>, context: &'static str) -> Result<String> {
    let text = String::from_utf8(bytes).map_err(|_| Error::InvalidRepoMutationRecord(context))?;
    Ok(text.trim_end_matches(['\r', '\n']).to_owned())
}

fn repo_key_hash(repo_key: &str) -> String {
    hex_bytes(&sha256_bytes(repo_key.as_bytes()))
}

fn repo_mutation_repo_key_hash(repo_ref: &RepoRef) -> String {
    repo_key_hash(&repo_mutation_repo_key(repo_ref))
}

fn repo_mutation_repo_key(repo_ref: &RepoRef) -> String {
    match repo_ref {
        RepoRef::LocalFolder { path, .. } => format!("local:{path}"),
        RepoRef::GitHubAtCommit { .. } => repo_ref.canonical(),
    }
}

fn sha256_bytes(bytes: &[u8]) -> RepoForkHash {
    let digest = Sha256::digest(bytes);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}

fn repo_mutation_seq_key(repo_key_hash: &str) -> Vec<u8> {
    prefixed_key(REPO_MUTATION_SEQ_KEY_PREFIX, repo_key_hash)
}

fn repo_mutation_snapshot_key(fork_hash: RepoForkHash) -> Vec<u8> {
    prefixed_key(REPO_MUTATION_SNAPSHOT_KEY_PREFIX, &hex_bytes(&fork_hash))
}

fn repo_mutation_oplog_prefix(repo_key_hash: &str) -> Vec<u8> {
    prefixed_key(REPO_MUTATION_OPLOG_KEY_PREFIX, repo_key_hash)
}

fn repo_mutation_oplog_key(repo_key_hash: &str, seq: u64) -> Vec<u8> {
    let mut key = repo_mutation_oplog_prefix(repo_key_hash);
    key.push(b':');
    key.extend_from_slice(format!("{seq:016x}").as_bytes());
    key
}

fn prefixed_key(prefix: &[u8], suffix: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + suffix.len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(suffix.as_bytes());
    key
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn is_executable(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}

fn set_executable(path: &Path, executable: bool) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if executable { 0o755 } else { 0o644 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, executable);
    }
    Ok(())
}

fn create_symlink(target: &Path, link: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (target, link);
        Err(Error::InvalidRepoMutationRecord(
            "symlink repo snapshots are unsupported on this platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use tempfile::TempDir;

    use super::*;
    use crate::types::ENTITY_TYPE_TASK;
    use crate::{ErrorKind, VaultConfig};

    fn open_test_vault() -> (TempDir, Vault) {
        let dir = tempfile::tempdir().expect("vault tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
        (dir, vault)
    }

    fn init_repo() -> TempDir {
        let dir = tempfile::tempdir().expect("repo tempdir");
        run_git_at_path(dir.path(), &["init".to_owned()]).expect("git init");
        fs::write(dir.path().join("README.md"), "base\n").expect("write readme");
        run_git_at_path(
            dir.path(),
            &["add".to_owned(), "--".to_owned(), "README.md".to_owned()],
        )
        .expect("git add");
        run_git_at_path(
            dir.path(),
            &[
                "-c".to_owned(),
                "user.name=Oneiron".to_owned(),
                "-c".to_owned(),
                "user.email=oneiron@example.invalid".to_owned(),
                "commit".to_owned(),
                "-m".to_owned(),
                "initial".to_owned(),
            ],
        )
        .expect("git commit");
        dir
    }

    fn repo_ref(repo: &TempDir) -> RepoRef {
        RepoRef::LocalFolder {
            path: repo.path().to_string_lossy().into_owned(),
            commit: current_head_commit(repo.path()).expect("repo head commit"),
        }
    }

    fn commit_file_at(repo: &TempDir, branch: &str, path: &str, content: &str, message: &str) {
        run_git_at_path(repo.path(), &["checkout".to_owned(), branch.to_owned()])
            .expect("checkout branch");
        fs::write(repo.path().join(path), content).expect("write branch file");
        run_git_at_path(
            repo.path(),
            &["add".to_owned(), "--".to_owned(), path.to_owned()],
        )
        .expect("git add branch file");
        run_git_at_path(
            repo.path(),
            &[
                "-c".to_owned(),
                "user.name=Oneiron".to_owned(),
                "-c".to_owned(),
                "user.email=oneiron@example.invalid".to_owned(),
                "commit".to_owned(),
                "-m".to_owned(),
                message.to_owned(),
            ],
        )
        .expect("git commit branch file");
    }

    fn create_conflicting_branches(repo: &TempDir) {
        let base = current_head_commit(repo.path()).expect("base commit");
        run_git_at_path(
            repo.path(),
            &[
                "checkout".to_owned(),
                "-B".to_owned(),
                "left".to_owned(),
                base.clone(),
            ],
        )
        .expect("checkout left from base");
        fs::write(repo.path().join("README.md"), "left branch\n").expect("write left");
        run_git_at_path(
            repo.path(),
            &["add".to_owned(), "--".to_owned(), "README.md".to_owned()],
        )
        .expect("add left");
        run_git_at_path(
            repo.path(),
            &[
                "-c".to_owned(),
                "user.name=Oneiron".to_owned(),
                "-c".to_owned(),
                "user.email=oneiron@example.invalid".to_owned(),
                "commit".to_owned(),
                "-m".to_owned(),
                "left edit".to_owned(),
            ],
        )
        .expect("commit left");

        run_git_at_path(
            repo.path(),
            &[
                "checkout".to_owned(),
                "-B".to_owned(),
                "right".to_owned(),
                base,
            ],
        )
        .expect("checkout right from base");
        fs::write(repo.path().join("README.md"), "right branch\n").expect("write right");
        run_git_at_path(
            repo.path(),
            &["add".to_owned(), "--".to_owned(), "README.md".to_owned()],
        )
        .expect("add right");
        run_git_at_path(
            repo.path(),
            &[
                "-c".to_owned(),
                "user.name=Oneiron".to_owned(),
                "-c".to_owned(),
                "user.email=oneiron@example.invalid".to_owned(),
                "commit".to_owned(),
                "-m".to_owned(),
                "right edit".to_owned(),
            ],
        )
        .expect("commit right");
        run_git_at_path(repo.path(), &["checkout".to_owned(), "left".to_owned()])
            .expect("return left");
    }

    fn put_branch_subject(vault: &Vault) -> EntityId {
        let branch_subject = EntityId::now();
        vault
            .put_entity(
                &branch_subject,
                ENTITY_TYPE_TASK,
                TimeRange { start: 1, end: 1 },
                1,
                b"repo branch",
            )
            .expect("branch subject");
        branch_subject
    }

    #[test]
    fn repo_mutation_queue_serializes_concurrent_commits() {
        let (_vault_dir, vault) = open_test_vault();
        let repo = init_repo();
        let vault = Arc::new(vault);
        let barrier = Arc::new(Barrier::new(3));

        let mut handles = Vec::new();
        for name in ["a", "b"] {
            let vault = Arc::clone(&vault);
            let barrier = Arc::clone(&barrier);
            let repo_ref = repo_ref(&repo);
            handles.push(thread::spawn(move || {
                barrier.wait();
                vault.apply_repo_mutation(RepoMutationRequest::new(
                    repo_ref,
                    RepoMutationOperation::CommitFile {
                        path: format!("{name}.txt"),
                        content: format!("{name}\n").into_bytes(),
                        message: format!("commit {name}"),
                    },
                ))
            }));
        }

        barrier.wait();
        let mut seqs = Vec::new();
        for handle in handles {
            let outcome = handle.join().expect("thread join").expect("commit");
            assert_eq!(outcome.entry.status, RepoMutationStatus::Applied);
            seqs.push(outcome.entry.seq);
        }
        seqs.sort_unstable();
        assert_eq!(seqs, vec![1, 2]);

        let log = vault.repo_mutation_oplog(&repo_ref(&repo)).expect("oplog");
        assert_eq!(log.len(), 2);
        assert!(log.iter().all(|entry| entry.failure.is_none()));
        assert_eq!(log[0].status, RepoMutationStatus::Applied);
        assert_eq!(log[1].status, RepoMutationStatus::Applied);

        let commits = run_git_at_path(
            repo.path(),
            &[
                "log".to_owned(),
                "--format=%s".to_owned(),
                "--".to_owned(),
                "a.txt".to_owned(),
                "b.txt".to_owned(),
            ],
        )
        .expect("git log");
        let commits = String::from_utf8(commits).expect("utf8 log");
        assert!(commits.contains("commit a"));
        assert!(commits.contains("commit b"));
    }

    #[cfg(unix)]
    #[test]
    fn repo_mutation_file_lock_uses_git_common_dir() {
        let repo = init_repo();
        let common_dir = git_common_dir(repo.path()).expect("main common dir");
        let worktree_parent = tempfile::tempdir().expect("worktree parent");
        let worktree_path = worktree_parent.path().join("linked-worktree");
        run_git_at_path(
            repo.path(),
            &[
                "worktree".to_owned(),
                "add".to_owned(),
                "--detach".to_owned(),
                "--".to_owned(),
                worktree_path.to_string_lossy().into_owned(),
                "HEAD".to_owned(),
            ],
        )
        .expect("create linked worktree");

        assert_eq!(
            git_common_dir(&worktree_path).expect("worktree common dir"),
            common_dir
        );
        let _guard = repo_mutation_file_lock(&common_dir).expect("lock common dir");
        assert!(common_dir.join(REPO_MUTATION_LOCK_FILE_NAME).exists());
    }

    #[test]
    fn repo_mutation_recovery_remounts_pre_action_snapshot() {
        let (_vault_dir, vault) = open_test_vault();
        let repo = init_repo();
        let tracked = repo.path().join("README.md");
        fs::write(&tracked, "dirty before\n").expect("dirty write");
        let before = fs::read_to_string(&tracked).expect("read before");

        let outcome = vault
            .apply_repo_mutation(RepoMutationRequest::new(
                repo_ref(&repo),
                RepoMutationOperation::CommitFile {
                    path: "README.md".to_owned(),
                    content: b"mutated\n".to_vec(),
                    message: "mutate readme".to_owned(),
                },
            ))
            .expect("mutate");
        let pre_head = run_git_at_path(
            repo.path(),
            &[
                "rev-parse".to_owned(),
                "--verify".to_owned(),
                "HEAD^".to_owned(),
            ],
        )
        .expect("pre mutation head");
        assert_eq!(
            fs::read_to_string(&tracked).expect("read mutated"),
            "mutated\n"
        );

        let recovery = vault
            .recover_repo_snapshot(&repo_ref(&repo), outcome.entry.pre_action_fork_hash)
            .expect("recover");
        assert_eq!(recovery.entry.operation_kind, "recover_snapshot");
        assert_eq!(
            fs::read_to_string(&tracked).expect("read recovered"),
            before
        );
        let recovered_head = run_git_at_path(
            repo.path(),
            &[
                "rev-parse".to_owned(),
                "--verify".to_owned(),
                "HEAD".to_owned(),
            ],
        )
        .expect("recovered head");
        assert_eq!(recovered_head, pre_head);
    }

    #[test]
    fn repo_mutation_auto_recovers_prepared_rows() {
        let (_vault_dir, vault) = open_test_vault();
        let repo = init_repo();
        let tracked = repo.path().join("README.md");
        let before = fs::read_to_string(&tracked).expect("read before");
        let input_ref = repo_ref(&repo);
        let repo_root = resolve_mutable_repo_root(&input_ref).expect("repo root");
        let canonical =
            canonical_repo_ref_for_root(&input_ref, &repo_root).expect("canonical repo");
        let request = RepoMutationRequest::new(
            canonical.clone(),
            RepoMutationOperation::CommitFile {
                path: "README.md".to_owned(),
                content: b"mutated\n".to_vec(),
                message: "mutate readme".to_owned(),
            },
        );
        let prepared = vault
            .prepare_repo_mutation(&canonical, &request, &repo_root)
            .expect("prepared row");
        fs::write(&tracked, "half applied\n").expect("simulate interrupted mutation");

        let recovered = vault
            .recover_prepared_repo_mutations(&canonical)
            .expect("recover prepared");

        assert_eq!(recovered.len(), 1);
        assert_eq!(
            fs::read_to_string(&tracked).expect("read recovered"),
            before
        );
        let log = vault.repo_mutation_oplog(&canonical).expect("oplog");
        assert_eq!(log[0].seq, prepared.seq);
        assert_eq!(log[0].status, RepoMutationStatus::Failed);
        assert_eq!(log[1].operation_kind, "recover_snapshot");
        assert_eq!(log[1].status, RepoMutationStatus::Applied);
    }

    #[cfg(unix)]
    #[test]
    fn repo_mutation_rejects_symlink_write_escape() {
        let (_vault_dir, vault) = open_test_vault();
        let repo = init_repo();
        let outside = tempfile::tempdir().expect("outside tempdir");
        std::os::unix::fs::symlink(outside.path(), repo.path().join("escape"))
            .expect("repo symlink");
        run_git_at_path(
            repo.path(),
            &["add".to_owned(), "--".to_owned(), "escape".to_owned()],
        )
        .expect("git add symlink");
        run_git_at_path(
            repo.path(),
            &[
                "-c".to_owned(),
                "user.name=Oneiron".to_owned(),
                "-c".to_owned(),
                "user.email=oneiron@example.invalid".to_owned(),
                "commit".to_owned(),
                "-m".to_owned(),
                "add symlink".to_owned(),
            ],
        )
        .expect("git commit symlink");

        let err = vault
            .apply_repo_mutation(RepoMutationRequest::new(
                repo_ref(&repo),
                RepoMutationOperation::CommitFile {
                    path: "escape/pwned".to_owned(),
                    content: b"owned\n".to_vec(),
                    message: "attempt escape".to_owned(),
                },
            ))
            .expect_err("symlink escape rejected");

        assert_eq!(err.kind(), ErrorKind::InvalidRepoMutationRecord);
        assert!(!outside.path().join("pwned").exists());
    }

    #[test]
    fn repo_mutation_commit_file_preserves_unrelated_staged_paths() {
        let (_vault_dir, vault) = open_test_vault();
        let repo = init_repo();
        fs::write(repo.path().join("unrelated.txt"), "staged\n").expect("write staged");
        run_git_at_path(
            repo.path(),
            &[
                "add".to_owned(),
                "--".to_owned(),
                "unrelated.txt".to_owned(),
            ],
        )
        .expect("stage unrelated");

        vault
            .apply_repo_mutation(RepoMutationRequest::new(
                repo_ref(&repo),
                RepoMutationOperation::CommitFile {
                    path: "owned.txt".to_owned(),
                    content: b"owned\n".to_vec(),
                    message: "commit owned".to_owned(),
                },
            ))
            .expect("commit owned");

        let staged = run_git_at_path(
            repo.path(),
            &[
                "diff".to_owned(),
                "--cached".to_owned(),
                "--name-only".to_owned(),
                "--".to_owned(),
                "unrelated.txt".to_owned(),
            ],
        )
        .expect("cached diff");
        assert_eq!(
            String::from_utf8(staged).expect("utf8 staged"),
            "unrelated.txt\n"
        );
        let unrelated_log = run_git_at_path(
            repo.path(),
            &[
                "log".to_owned(),
                "--format=%s".to_owned(),
                "--".to_owned(),
                "unrelated.txt".to_owned(),
            ],
        )
        .expect("unrelated log");
        assert!(
            !String::from_utf8(unrelated_log)
                .expect("utf8 log")
                .contains("commit owned")
        );
    }

    #[test]
    fn repo_mutation_recovery_rejects_snapshot_from_other_repo() {
        let (_vault_dir, vault) = open_test_vault();
        let repo_a = init_repo();
        let repo_b = init_repo();
        fs::write(repo_a.path().join("repo-a-only.txt"), "repo a only\n")
            .expect("write repo a unique file");
        run_git_at_path(
            repo_a.path(),
            &[
                "add".to_owned(),
                "--".to_owned(),
                "repo-a-only.txt".to_owned(),
            ],
        )
        .expect("git add repo a unique file");
        run_git_at_path(
            repo_a.path(),
            &[
                "-c".to_owned(),
                "user.name=Oneiron".to_owned(),
                "-c".to_owned(),
                "user.email=oneiron@example.invalid".to_owned(),
                "commit".to_owned(),
                "-m".to_owned(),
                "make repo a unique".to_owned(),
            ],
        )
        .expect("git commit repo a unique file");
        let b_readme = repo_b.path().join("README.md");
        let before_b = fs::read_to_string(&b_readme).expect("read repo b");

        let outcome = vault
            .apply_repo_mutation(RepoMutationRequest::new(
                repo_ref(&repo_a),
                RepoMutationOperation::CommitFile {
                    path: "a.txt".to_owned(),
                    content: b"a\n".to_vec(),
                    message: "commit a".to_owned(),
                },
            ))
            .expect("mutate repo a");
        let err = vault
            .recover_repo_snapshot(&repo_ref(&repo_b), outcome.entry.pre_action_fork_hash)
            .expect_err("foreign snapshot rejected");

        assert_eq!(err.kind(), ErrorKind::InvalidRepoMutationRecord);
        assert_eq!(
            fs::read_to_string(&b_readme).expect("read repo b after"),
            before_b
        );
    }

    #[test]
    fn repo_conflict_record_keeps_branches_mountable_and_queryable() {
        let (_vault_dir, vault) = open_test_vault();
        let repo = init_repo();
        create_conflicting_branches(&repo);
        let branch_subject = put_branch_subject(&vault);

        let outcome = vault
            .apply_repo_mutation(RepoMutationRequest::new(
                repo_ref(&repo),
                RepoMutationOperation::RecordConflict {
                    branch_subject,
                    branch_name: "left".to_owned(),
                    ours_ref: "left".to_owned(),
                    theirs_ref: "right".to_owned(),
                },
            ))
            .expect("record conflict");
        assert_eq!(outcome.entry.status, RepoMutationStatus::Applied);
        let claim_id = outcome
            .repo_conflict_claim_id
            .expect("record conflict claim id");

        let conflicts = vault
            .repo_conflict_claims(&branch_subject)
            .expect("conflict claims");
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].claim_id, claim_id);
        assert_eq!(conflicts[0].branch, "left");
        assert_eq!(conflicts[0].conflicted_paths, vec!["README.md"]);
        assert_eq!(conflicts[0].base_tree.len(), CODEBASE_COMMIT_HASH_HEX_LEN);
        assert_eq!(conflicts[0].ours_tree.len(), CODEBASE_COMMIT_HASH_HEX_LEN);
        assert_eq!(conflicts[0].theirs_tree.len(), CODEBASE_COMMIT_HASH_HEX_LEN);

        let worktree_parent = tempfile::tempdir().expect("worktree parent");
        let left_mount = worktree_parent.path().join("left");
        let right_mount = worktree_parent.path().join("right");
        run_git_at_path(
            repo.path(),
            &[
                "worktree".to_owned(),
                "add".to_owned(),
                "--detach".to_owned(),
                "--".to_owned(),
                left_mount.to_string_lossy().into_owned(),
                "left".to_owned(),
            ],
        )
        .expect("mount left");
        run_git_at_path(
            repo.path(),
            &[
                "worktree".to_owned(),
                "add".to_owned(),
                "--detach".to_owned(),
                "--".to_owned(),
                right_mount.to_string_lossy().into_owned(),
                "right".to_owned(),
            ],
        )
        .expect("mount right");
        assert_eq!(
            fs::read_to_string(left_mount.join("README.md")).expect("left readme"),
            "left branch\n"
        );
        assert_eq!(
            fs::read_to_string(right_mount.join("README.md")).expect("right readme"),
            "right branch\n"
        );

        commit_file_at(
            &repo,
            "left",
            "left.txt",
            "left descendant\n",
            "left descendant",
        );
        commit_file_at(
            &repo,
            "right",
            "right.txt",
            "right descendant\n",
            "right descendant",
        );
        let left_log = run_git_at_path(
            repo.path(),
            &[
                "log".to_owned(),
                "--format=%s".to_owned(),
                "left".to_owned(),
            ],
        )
        .expect("left log");
        let right_log = run_git_at_path(
            repo.path(),
            &[
                "log".to_owned(),
                "--format=%s".to_owned(),
                "right".to_owned(),
            ],
        )
        .expect("right log");
        assert!(
            String::from_utf8(left_log)
                .expect("utf8 left log")
                .contains("left descendant")
        );
        assert!(
            String::from_utf8(right_log)
                .expect("utf8 right log")
                .contains("right descendant")
        );
    }

    #[test]
    fn repo_conflict_resolution_supersedes_open_claim_and_writes_clean_tree() {
        let (_vault_dir, vault) = open_test_vault();
        let repo = init_repo();
        create_conflicting_branches(&repo);
        let branch_subject = put_branch_subject(&vault);
        let open = vault
            .apply_repo_mutation(RepoMutationRequest::new(
                repo_ref(&repo),
                RepoMutationOperation::RecordConflict {
                    branch_subject,
                    branch_name: "left".to_owned(),
                    ours_ref: "left".to_owned(),
                    theirs_ref: "right".to_owned(),
                },
            ))
            .expect("record conflict")
            .repo_conflict_claim_id
            .expect("open claim id");

        run_git_at_path(repo.path(), &["checkout".to_owned(), "left".to_owned()])
            .expect("checkout left");
        let resolved = vault
            .apply_repo_mutation(RepoMutationRequest::new(
                repo_ref(&repo),
                RepoMutationOperation::ResolveConflictFile {
                    branch_subject,
                    open_conflict_claim_id: open,
                    branch_name: "left".to_owned(),
                    path: "README.md".to_owned(),
                    content: b"resolved branch\n".to_vec(),
                    message: "resolve readme conflict".to_owned(),
                },
            ))
            .expect("resolve conflict")
            .repo_conflict_claim_id
            .expect("resolution claim id");

        let status = run_git_at_path(
            repo.path(),
            &["status".to_owned(), "--porcelain".to_owned()],
        )
        .expect("git status");
        assert_eq!(String::from_utf8(status).expect("utf8 status"), "");
        assert_eq!(
            fs::read_to_string(repo.path().join("README.md")).expect("resolved file"),
            "resolved branch\n"
        );
        assert!(
            vault
                .repo_conflict_claims(&branch_subject)
                .expect("active open conflicts")
                .is_empty()
        );
        let open_body = vault
            .get_claim(&open)
            .expect("get open claim")
            .expect("open claim exists");
        assert_eq!(open_body.lifecycle, ClaimLifecycleStatus::Superseded);
        let resolutions = vault
            .repo_conflict_resolution_claims(&branch_subject)
            .expect("resolution claims");
        assert_eq!(resolutions.len(), 1);
        assert_eq!(resolutions[0].claim_id, resolved);
        assert_eq!(resolutions[0].open_conflict_claim_id, open);
        assert_eq!(resolutions[0].resolved_paths, vec!["README.md"]);
        assert_eq!(
            resolutions[0].resolved_tree,
            tree_hash_for_ref(repo.path(), "HEAD").expect("resolved tree")
        );
    }

    #[test]
    fn repo_mutation_api_has_no_forbidden_raw_git_operations() {
        assert_eq!(
            REPO_MUTATION_ALLOWED_OPERATION_KINDS,
            [
                "commit_file",
                "create_worktree",
                "record_conflict",
                "remove_worktree",
                "recover_snapshot",
                "resolve_conflict_file"
            ]
        );
        for forbidden in REPO_MUTATION_FORBIDDEN_GIT_COMMANDS {
            assert!(
                !REPO_MUTATION_ALLOWED_OPERATION_KINDS.contains(&forbidden),
                "{forbidden} must not be an allowed queue operation"
            );
        }
        let err = validate_relative_repo_path(".git/index").expect_err("reject .git path");
        assert_eq!(err.kind(), ErrorKind::InvalidRepoMutationRecord);
        let err = validate_relative_repo_path("../outside").expect_err("reject parent path");
        assert_eq!(err.kind(), ErrorKind::InvalidRepoMutationRecord);
        let err = validate_base_ref("-q").expect_err("reject option-like base ref");
        assert_eq!(err.kind(), ErrorKind::InvalidRepoMutationRecord);
        let truncated = truncate_failure(&format!("{}é{}", "a".repeat(4095), "b".repeat(16)));
        assert!(truncated.ends_with("..."));
    }

    #[test]
    fn repo_mutation_worktree_lifecycle_is_queued_and_logged() {
        let (_vault_dir, vault) = open_test_vault();
        let repo = init_repo();
        let worktree = tempfile::tempdir().expect("worktree parent");
        let worktree_path = worktree.path().join("agent-worktree");

        let created = vault
            .apply_repo_mutation(RepoMutationRequest::new(
                repo_ref(&repo),
                RepoMutationOperation::CreateWorktree {
                    worktree_path: worktree_path.clone(),
                    base_ref: "HEAD".to_owned(),
                },
            ))
            .expect("create worktree");
        assert!(worktree_path.join("README.md").exists());

        let removed = vault
            .apply_repo_mutation(RepoMutationRequest::new(
                repo_ref(&repo),
                RepoMutationOperation::RemoveWorktree {
                    worktree_path: worktree_path.clone(),
                },
            ))
            .expect("remove worktree");
        assert!(!worktree_path.exists());
        assert_eq!(created.entry.seq, 1);
        assert_eq!(removed.entry.seq, 2);
    }
}
