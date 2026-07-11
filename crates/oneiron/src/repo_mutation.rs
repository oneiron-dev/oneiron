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
use crate::affect::Vad;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, PREDICATE_CONFLICT_OPEN,
    PREDICATE_CONFLICT_RESOLVED, decode_claim_body, encode_claim_body,
};
use crate::codebase::CODEBASE_COMMIT_HASH_HEX_LEN;
use crate::codebase::{CODEBASE_FILE_PATH_MAX_BYTES, RepoRef};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::temporal::TimeRange;

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
pub const REPO_PROVENANCE_TRAILER_KEY: &str = "Oneiron-Claim";
pub const REPO_PROVENANCE_NOTES_REF: &str = "refs/notes/oneiron-provenance";
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
pub const REPO_PROVENANCE_PREDICATE: &str = "repo.provenance";
pub const REPO_PROVENANCE_VALUE_KEYS: [&str; 5] = [
    "actor",
    "model",
    "prompt_hash",
    "derivation_envelope",
    "diff_lineage_receipt",
];
pub const REPO_PROVENANCE_DERIVATION_ENVELOPE_KEYS: [&str; 4] =
    ["content_hash", "model_id", "version", "params_hash"];

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
const REPO_PROVENANCE_TRAILER_PREFIX: &str = "Oneiron-Claim:";
const REPO_PROVENANCE_GIT_AUTHOR_NAME: &str = "Oneiron";
const REPO_PROVENANCE_GIT_AUTHOR_EMAIL: &str = "oneiron@example.invalid";
const REPO_PROVENANCE_GIT_LOG_FIELD_SEPARATOR: u8 = 0x00;
const REPO_PROVENANCE_GIT_LOG_RECORD_SEPARATOR: u8 = 0x1e;

static REPO_MUTATION_LOCKS: LazyLock<Mutex<HashMap<String, Arc<Mutex<()>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static REPO_MUTATION_WORKTREE_COUNTER: AtomicU64 = AtomicU64::new(1);

#[cfg(test)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum RepoMutationCrashPoint {
    #[default]
    None,
    AfterPreparedBeforeAction,
    AfterActionBeforeApplied,
}

#[cfg(test)]
thread_local! {
    static INJECT_REPO_MUTATION_CRASH: std::cell::Cell<RepoMutationCrashPoint> =
        const { std::cell::Cell::new(RepoMutationCrashPoint::None) };
}

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

#[derive(Debug)]
struct PreparedRepoMutationAction {
    oplog: PreparedRepoMutation,
    execution: PreparedRepoMutationExecution,
}

#[derive(Debug)]
enum PreparedRepoMutationExecution {
    Direct,
    CommitFile(PreparedCommitFile),
}

#[derive(Debug)]
struct PreparedCommitFile {
    worktree_path: PathBuf,
    base_head: String,
    new_head: String,
}

impl PreparedRepoMutationExecution {
    fn commit_file(&self) -> Result<&PreparedCommitFile> {
        let Self::CommitFile(prepared) = self else {
            return Err(Error::InvariantViolation(
                "commit-producing repo mutation missing prepared commit",
            ));
        };
        Ok(prepared)
    }

    fn cleanup(&self, repo_root: &Path) -> Result<()> {
        match self {
            Self::Direct => Ok(()),
            Self::CommitFile(prepared) => remove_queue_worktree(repo_root, &prepared.worktree_path),
        }
    }
}

#[cfg(test)]
fn take_repo_mutation_crash(point: RepoMutationCrashPoint) -> bool {
    INJECT_REPO_MUTATION_CRASH.with(|cell| {
        if cell.get() == point {
            cell.set(RepoMutationCrashPoint::None);
            true
        } else {
            false
        }
    })
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
    #[serde(default)]
    expected_post_action_fork_hash: Option<RepoForkHash>,
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
        validate_repo_provenance_request(self, &request)?;
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
        #[cfg(test)]
        if take_repo_mutation_crash(RepoMutationCrashPoint::AfterPreparedBeforeAction) {
            let _ = prepared.execution.cleanup(&repo_root);
            return Err(Error::InvariantViolation(
                "test: injected repo mutation crash after Prepared before action",
            ));
        }

        let execution =
            execute_repo_mutation(self, &repo_ref, &repo_root, &request, &prepared.execution);
        let cleanup = prepared.execution.cleanup(&repo_root);
        let execution = match (execution, cleanup) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok(repo_conflict_claim_id), Ok(())) => Ok(repo_conflict_claim_id),
        };

        #[cfg(test)]
        if execution.is_ok()
            && take_repo_mutation_crash(RepoMutationCrashPoint::AfterActionBeforeApplied)
        {
            return Err(Error::InvariantViolation(
                "test: injected repo mutation crash after action before Applied",
            ));
        }

        match execution {
            Ok(repo_conflict_claim_id) => {
                let entry = self.finish_repo_mutation(
                    &prepared.oplog,
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
                    &prepared.oplog,
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

    /// Detects prepared repo mutation oplog rows and compares the current repo
    /// state with each row's write-ahead intent.
    ///
    /// A repo already at the expected post-state is rolled forward to
    /// `applied`. A repo still at the pre-state is remounted from the recorded
    /// snapshot and the interrupted row is marked `failed`. Any other state is
    /// left untouched for manual resolution.
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
            let (actual_fork_hash, _) = capture_repo_snapshot(repo_root)?;
            if stale
                .expected_post_action_fork_hash
                .is_some_and(|expected| {
                    expected != stale.pre_action_fork_hash && actual_fork_hash == expected
                })
            {
                let entry = self.finish_repo_mutation(
                    &PreparedRepoMutation {
                        repo_key_hash: repo_mutation_repo_key_hash(repo_ref),
                        seq: stale.seq,
                    },
                    RepoMutationStatus::Applied,
                    None,
                    now_millis(),
                )?;
                outcomes.push(RepoMutationOutcome {
                    entry,
                    repo_conflict_claim_id: None,
                });
                continue;
            }

            if actual_fork_hash != stale.pre_action_fork_hash {
                return Err(Error::RepoMutationRecoveryDiverged {
                    seq: stale.seq,
                    pre_action_fork_hash: Box::new(stale.pre_action_fork_hash),
                    expected_post_action_fork_hash: stale
                        .expected_post_action_fork_hash
                        .map(Box::new),
                    actual_fork_hash: Box::new(actual_fork_hash),
                });
            }

            let request = RepoMutationRequest {
                repo_ref: repo_ref.clone(),
                actor_id: stale.actor_id,
                session_id: stale.session_id,
                provenance_claim_id: None,
                operation: RepoMutationOperation::RecoverSnapshot {
                    fork_hash: stale.pre_action_fork_hash,
                },
            };
            let recovery = self.prepare_repo_mutation(repo_ref, &request, repo_root)?;
            let execution =
                execute_repo_mutation(self, repo_ref, repo_root, &request, &recovery.execution);
            let cleanup = recovery.execution.cleanup(repo_root);
            let execution = match (execution, cleanup) {
                (Err(error), _) => Err(error),
                (Ok(_), Err(error)) => Err(error),
                (Ok(repo_conflict_claim_id), Ok(())) => Ok(repo_conflict_claim_id),
            };
            match execution {
                Ok(_) => {
                    let entry = self.finish_repo_mutation(
                        &recovery.oplog,
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
                        &recovery.oplog,
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
    ) -> Result<PreparedRepoMutationAction> {
        let (fork_hash, snapshot_bytes) = capture_repo_snapshot(repo_root)?;
        let pre_action_snapshot = decode_snapshot(&snapshot_bytes)?;
        let execution = prepare_repo_mutation_execution(repo_root, request)?;
        let prepared = (|| -> Result<PreparedRepoMutation> {
            let expected_post_action_fork_hash = expected_post_action_fork_hash(
                &request.operation,
                &pre_action_snapshot,
                fork_hash,
                &execution,
            )?;
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
                expected_post_action_fork_hash: Some(expected_post_action_fork_hash),
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
        })();
        match prepared {
            Ok(oplog) => Ok(PreparedRepoMutationAction { oplog, execution }),
            Err(error) => {
                let _ = execution.cleanup(repo_root);
                Err(error)
            }
        }
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

fn prepare_repo_mutation_execution(
    repo_root: &Path,
    request: &RepoMutationRequest,
) -> Result<PreparedRepoMutationExecution> {
    let commit = match &request.operation {
        RepoMutationOperation::CommitFile {
            path,
            content,
            message,
        }
        | RepoMutationOperation::ResolveConflictFile {
            path,
            content,
            message,
            ..
        } => Some((path.as_str(), content.as_slice(), message.as_str())),
        _ => None,
    };
    let Some((path, content, message)) = commit else {
        return Ok(PreparedRepoMutationExecution::Direct);
    };
    let message = commit_message_with_provenance_trailer(message, request.provenance_claim_id)?;
    prepare_commit_file_through_queue_worktree(repo_root, path, content, &message)
        .map(PreparedRepoMutationExecution::CommitFile)
}

fn expected_post_action_fork_hash(
    operation: &RepoMutationOperation,
    pre_action_snapshot: &StoredRepoSnapshot,
    pre_action_fork_hash: RepoForkHash,
    execution: &PreparedRepoMutationExecution,
) -> Result<RepoForkHash> {
    let (path, content) = match operation {
        RepoMutationOperation::CommitFile { path, content, .. }
        | RepoMutationOperation::ResolveConflictFile { path, content, .. } => {
            (path.as_str(), content.as_slice())
        }
        RepoMutationOperation::RecoverSnapshot { fork_hash } => return Ok(*fork_hash),
        RepoMutationOperation::CreateWorktree { .. }
        | RepoMutationOperation::RecordConflict { .. }
        | RepoMutationOperation::RemoveWorktree { .. } => return Ok(pre_action_fork_hash),
    };
    let prepared = execution.commit_file()?;
    if pre_action_snapshot.head.as_deref() != Some(prepared.base_head.as_str()) {
        return Err(Error::ConcurrentWrite(
            "repo HEAD changed while preparing write-ahead intent",
        ));
    }
    let mut post_action_snapshot = pre_action_snapshot.clone();
    post_action_snapshot.head = Some(prepared.new_head.clone());
    let executable = post_action_snapshot
        .entries
        .iter()
        .find(|entry| entry.path == path && entry.kind == StoredRepoSnapshotEntryKind::File)
        .is_some_and(|entry| entry.executable);
    post_action_snapshot
        .entries
        .retain(|entry| entry.path != path);
    post_action_snapshot.entries.push(StoredRepoSnapshotEntry {
        path: path.to_owned(),
        kind: StoredRepoSnapshotEntryKind::File,
        executable,
        content: content.to_vec(),
        symlink_target: None,
    });
    post_action_snapshot
        .entries
        .sort_by(|left, right| left.path.cmp(&right.path));
    Ok(sha256_bytes(&encode_snapshot(&post_action_snapshot)?))
}

fn execute_repo_mutation(
    vault: &Vault,
    repo_ref: &RepoRef,
    repo_root: &Path,
    request: &RepoMutationRequest,
    execution: &PreparedRepoMutationExecution,
) -> Result<Option<EntityId>> {
    match &request.operation {
        RepoMutationOperation::CommitFile {
            path,
            content,
            message,
        } => {
            validate_relative_repo_path(path)?;
            let _ = commit_message_with_provenance_trailer(message, request.provenance_claim_id)?;
            apply_prepared_commit_file(repo_root, path, content, execution.commit_file()?)?;
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
                request.provenance_claim_id,
                execution.commit_file()?,
            )?;
            Ok(Some(claim_id))
        }
    }
}

fn validate_repo_provenance_request(vault: &Vault, request: &RepoMutationRequest) -> Result<()> {
    let Some(claim_id) = request.provenance_claim_id else {
        return Ok(());
    };
    match &request.operation {
        RepoMutationOperation::CommitFile { .. }
        | RepoMutationOperation::ResolveConflictFile { .. } => {
            require_repo_provenance_claim(vault, &claim_id)
        }
        _ => Err(Error::InvalidRepoMutationRecord(
            "provenance claim id only applies to commit-producing repo mutations",
        )),
    }
}

fn require_repo_provenance_claim(vault: &Vault, claim_id: &EntityId) -> Result<()> {
    let raw = vault.get_raw(claim_id)?.ok_or(Error::EntityNotFound)?;
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return Err(Error::InvalidRepoMutationRecord(
            "provenance claim id must reference a CLAIM entity",
        ));
    }
    let body = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    validate_repo_provenance_claim_body(&body)?;
    Ok(())
}

fn validate_repo_provenance_claim_body(body: &ClaimBody) -> Result<()> {
    if body.predicate != REPO_PROVENANCE_PREDICATE {
        return Err(Error::InvalidRepoMutationRecord(
            "repo provenance claim must use the repo.provenance predicate",
        ));
    }
    if body.lifecycle != ClaimLifecycleStatus::Active {
        return Err(Error::InvalidRepoMutationRecord(
            "repo provenance claim must be active",
        ));
    }
    let entries = msgpack_map_entries(
        &body.value,
        "repo provenance claim value must be a PROV-AGENT map",
    )?;
    require_nonblank_msgpack_string(entries, "actor")?;
    require_nonblank_msgpack_string(entries, "model")?;
    require_nonblank_msgpack_string(entries, "prompt_hash")?;
    let envelope = require_msgpack_map(entries, "derivation_envelope")?;
    for key in REPO_PROVENANCE_DERIVATION_ENVELOPE_KEYS {
        require_nonblank_msgpack_string(envelope, key)?;
    }
    let receipt = require_msgpack_map(entries, "diff_lineage_receipt")?;
    if receipt.is_empty() {
        return Err(Error::InvalidRepoMutationRecord(
            "repo provenance diff_lineage_receipt must be a non-empty map",
        ));
    }
    Ok(())
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
    provenance_claim_id: Option<EntityId>,
    prepared_commit: &PreparedCommitFile,
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

    let _ = commit_message_with_provenance_trailer(message, provenance_claim_id)?;
    apply_prepared_commit_file(repo_root, path, content, prepared_commit)?;
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

fn msgpack_map_entries<'a>(
    value: &'a Value,
    context: &'static str,
) -> Result<&'a [(Value, Value)]> {
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(Error::InvalidRepoMutationRecord(context)),
    }
}

fn require_msgpack_map<'a>(
    entries: &'a [(Value, Value)],
    key: &str,
) -> Result<&'a [(Value, Value)]> {
    let value = require_unique_msgpack_key(entries, key)?;
    msgpack_map_entries(value, "repo provenance nested field must be a map")
}

fn require_nonblank_msgpack_string(entries: &[(Value, Value)], key: &str) -> Result<()> {
    let value = require_unique_msgpack_key(entries, key)?;
    let Some(value) = value.as_str() else {
        return Err(Error::InvalidRepoMutationRecord(
            "repo provenance field must be a string",
        ));
    };
    if value.trim().is_empty() {
        return Err(Error::InvalidRepoMutationRecord(
            "repo provenance field must be non-empty",
        ));
    }
    Ok(())
}

fn require_unique_msgpack_key<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    let mut found = None;
    for (candidate, value) in entries {
        if candidate.as_str() == Some(key) && found.replace(value).is_some() {
            return Err(Error::InvalidRepoMutationRecord(
                "repo provenance claim value must not duplicate required keys",
            ));
        }
    }
    found.ok_or(Error::InvalidRepoMutationRecord(
        "repo provenance claim value is missing a required key",
    ))
}

fn final_trailer_block(message: &str) -> Option<Vec<&str>> {
    let trimmed = message.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() {
        return None;
    }
    let lines = trimmed.lines().collect::<Vec<_>>();
    let mut start = lines.len();
    while start > 0 && !lines[start - 1].trim().is_empty() {
        start -= 1;
    }
    if start == 0 {
        return None;
    }
    let block = lines[start..].to_vec();
    if block.is_empty() || !block.iter().all(|line| is_git_trailer_line(line)) {
        return None;
    }
    Some(block)
}

fn has_final_trailer_block(message: &str) -> bool {
    final_trailer_block(message).is_some()
}

fn is_git_trailer_line(line: &str) -> bool {
    let Some((key, value)) = line.split_once(':') else {
        return false;
    };
    !key.is_empty()
        && !value.trim().is_empty()
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

pub fn parse_repo_provenance_trailer(message: &str) -> Result<Option<EntityId>> {
    let mut found = None;
    let Some(block) = final_trailer_block(message) else {
        return Ok(None);
    };
    for line in block {
        let Some(raw_claim_id) = line.strip_prefix(REPO_PROVENANCE_TRAILER_PREFIX) else {
            continue;
        };
        let claim_id = raw_claim_id.trim();
        if claim_id.is_empty() || claim_id.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(Error::InvalidRepoMutationRecord(
                "repo provenance trailer claim id must be one token",
            ));
        }
        let claim_id = EntityId::from_hex(claim_id).map_err(|_| {
            Error::InvalidRepoMutationRecord(
                "repo provenance trailer claim id must be a 32-hex entity id",
            )
        })?;
        if found.replace(claim_id).is_some() {
            return Err(Error::InvalidRepoMutationRecord(
                "commit message must not contain multiple repo provenance trailers",
            ));
        }
    }
    Ok(found)
}

pub fn repo_commit_provenance(
    repo_root: &Path,
    commit_sha: &str,
) -> Result<Option<RepoCommitProvenance>> {
    let commit_sha = canonical_commit_sha(repo_root, commit_sha)?;
    let message_bytes = run_git(
        repo_root,
        &[
            "show".to_owned(),
            "-s".to_owned(),
            "--format=%B".to_owned(),
            commit_sha.clone(),
        ],
    )?;
    let message = String::from_utf8_lossy(&message_bytes);
    Ok(
        parse_repo_provenance_trailer(&message)?.map(|claim_id| RepoCommitProvenance {
            commit_sha,
            claim_id,
        }),
    )
}

pub fn repo_commit_for_provenance_claim(
    repo_root: &Path,
    claim_id: &EntityId,
) -> Result<Option<String>> {
    let trailer = format!("{REPO_PROVENANCE_TRAILER_KEY}: {}", claim_id.to_hex());
    let output = run_git(
        repo_root,
        &[
            "log".to_owned(),
            "--branches".to_owned(),
            "--tags".to_owned(),
            "--remotes".to_owned(),
            "--fixed-strings".to_owned(),
            "--grep".to_owned(),
            trailer,
            format!(
                "--format=%H%x{:02x}%B%x{:02x}",
                REPO_PROVENANCE_GIT_LOG_FIELD_SEPARATOR, REPO_PROVENANCE_GIT_LOG_RECORD_SEPARATOR
            ),
        ],
    )?;
    let mut found = None;
    for record in output.split(|byte| *byte == REPO_PROVENANCE_GIT_LOG_RECORD_SEPARATOR) {
        let record = trim_git_log_record_prefix(record);
        if record.is_empty() {
            continue;
        }
        let Some(commit_sha) = repo_commit_for_provenance_claim_record(record, claim_id)? else {
            continue;
        };
        if found.replace(commit_sha).is_some() {
            return Err(Error::InvalidRepoMutationRecord(
                "repo provenance claim id maps to multiple commits",
            ));
        }
    }
    Ok(found)
}

fn trim_git_log_record_prefix(mut record: &[u8]) -> &[u8] {
    while matches!(record.first(), Some(b'\r' | b'\n')) {
        record = &record[1..];
    }
    record
}

fn repo_commit_for_provenance_claim_record(
    record: &[u8],
    claim_id: &EntityId,
) -> Result<Option<String>> {
    let Some(separator) = record
        .iter()
        .position(|byte| *byte == REPO_PROVENANCE_GIT_LOG_FIELD_SEPARATOR)
    else {
        return Err(Error::InvalidRepoMutationRecord(
            "git log provenance record missing commit separator",
        ));
    };
    let commit_sha = std::str::from_utf8(&record[..separator])
        .map_err(|_| Error::InvalidRepoMutationRecord("git log commit sha must be UTF-8"))?
        .trim();
    validate_git_object_hash(commit_sha, "git log commit sha must be a 40-hex commit")?;
    let message = String::from_utf8_lossy(&record[separator + 1..]);
    let Some(recorded_claim_id) = parse_repo_provenance_trailer(&message)? else {
        return Ok(None);
    };
    if recorded_claim_id == *claim_id {
        return Ok(Some(commit_sha.to_ascii_lowercase()));
    }
    Ok(None)
}

pub fn export_repo_provenance_git_note(
    repo_root: &Path,
    commit_sha: &str,
    claim_id: &EntityId,
) -> Result<()> {
    let commit_sha = canonical_commit_sha(repo_root, commit_sha)?;
    let note = repo_provenance_git_note_payload(&commit_sha, claim_id);
    run_git(
        repo_root,
        &[
            "-c".to_owned(),
            format!("user.name={REPO_PROVENANCE_GIT_AUTHOR_NAME}"),
            "-c".to_owned(),
            format!("user.email={REPO_PROVENANCE_GIT_AUTHOR_EMAIL}"),
            "notes".to_owned(),
            "--ref".to_owned(),
            REPO_PROVENANCE_NOTES_REF.to_owned(),
            "add".to_owned(),
            "-f".to_owned(),
            "-m".to_owned(),
            note,
            commit_sha,
        ],
    )?;
    Ok(())
}

pub fn repo_provenance_git_note(repo_root: &Path, commit_sha: &str) -> Result<Option<String>> {
    let commit_sha = canonical_commit_sha(repo_root, commit_sha)?;
    let Some(note) = git_output_optional(
        repo_root,
        &[
            "notes".to_owned(),
            "--ref".to_owned(),
            REPO_PROVENANCE_NOTES_REF.to_owned(),
            "show".to_owned(),
            commit_sha,
        ],
    )?
    else {
        return Ok(None);
    };
    let note = String::from_utf8(note)
        .map_err(|_| Error::InvalidRepoMutationRecord("git notes payload must be UTF-8"))?;
    Ok(Some(note.trim_end_matches(['\r', '\n']).to_owned()))
}

pub fn repo_commit_provenance_from_git_note(
    repo_root: &Path,
    commit_sha: &str,
) -> Result<Option<RepoCommitProvenance>> {
    let commit_sha = canonical_commit_sha(repo_root, commit_sha)?;
    let Some(note) = repo_provenance_git_note(repo_root, &commit_sha)? else {
        return Ok(None);
    };
    let payload: RepoProvenanceGitNotePayload = serde_json::from_str(&note)
        .map_err(|_| Error::InvalidRepoMutationRecord("git notes provenance payload invalid"))?;
    if payload.trailer != REPO_PROVENANCE_TRAILER_KEY {
        return Err(Error::InvalidRepoMutationRecord(
            "git notes provenance trailer key mismatch",
        ));
    }
    validate_git_object_hash(
        &payload.commit,
        "git notes provenance commit must be a 40-hex commit",
    )?;
    if payload.commit.to_ascii_lowercase() != commit_sha {
        return Err(Error::InvalidRepoMutationRecord(
            "git notes provenance commit mismatch",
        ));
    }
    let claim_id = EntityId::from_hex(&payload.claim_id).map_err(|_| {
        Error::InvalidRepoMutationRecord("git notes provenance claim id must be 32-hex")
    })?;
    Ok(Some(RepoCommitProvenance {
        commit_sha,
        claim_id,
    }))
}

fn commit_message_with_provenance_trailer(
    message: &str,
    claim_id: Option<EntityId>,
) -> Result<String> {
    validate_commit_message(message)?;
    let Some(claim_id) = claim_id else {
        return Ok(message.to_owned());
    };
    if parse_repo_provenance_trailer(message)?.is_some() {
        return Err(Error::InvalidRepoMutationRecord(
            "commit message must not predefine the repo provenance trailer",
        ));
    }
    let message = message.trim_end_matches(['\r', '\n']);
    let separator = if has_final_trailer_block(message) {
        "\n"
    } else {
        "\n\n"
    };
    let message = format!(
        "{message}{separator}{REPO_PROVENANCE_TRAILER_KEY}: {}\n",
        claim_id.to_hex()
    );
    validate_commit_message(&message)?;
    Ok(message)
}

#[derive(Deserialize)]
struct RepoProvenanceGitNotePayload {
    commit: String,
    claim_id: String,
    trailer: String,
}

fn repo_provenance_git_note_payload(commit_sha: &str, claim_id: &EntityId) -> String {
    format!(
        "{{\"commit\":\"{commit_sha}\",\"claim_id\":\"{}\",\"trailer\":\"{REPO_PROVENANCE_TRAILER_KEY}\"}}",
        claim_id.to_hex()
    )
}

fn canonical_commit_sha(repo_root: &Path, commit_sha: &str) -> Result<String> {
    validate_git_object_hash(commit_sha, "commit sha must be a 40-hex commit")?;
    let commit_sha = utf8_trimmed(
        run_git(
            repo_root,
            &[
                "rev-parse".to_owned(),
                "--verify".to_owned(),
                format!("{commit_sha}^{{commit}}"),
            ],
        )?,
        "git commit sha must be UTF-8",
    )?;
    validate_git_object_hash(&commit_sha, "resolved commit sha must be a 40-hex commit")?;
    Ok(commit_sha.to_ascii_lowercase())
}

fn prepare_commit_file_through_queue_worktree(
    repo_root: &Path,
    path: &str,
    content: &[u8],
    message: &str,
) -> Result<PreparedCommitFile> {
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
    let preparation = (|| -> Result<PreparedCommitFile> {
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
        Ok(PreparedCommitFile {
            worktree_path: worktree_path.clone(),
            base_head,
            new_head,
        })
    })();
    match preparation {
        Ok(prepared) => Ok(prepared),
        Err(error) => {
            let _ = remove_queue_worktree(repo_root, &worktree_path);
            Err(error)
        }
    }
}

fn apply_prepared_commit_file(
    repo_root: &Path,
    path: &str,
    content: &[u8],
    prepared: &PreparedCommitFile,
) -> Result<()> {
    write_repo_file_no_symlink(repo_root, path, content)?;
    run_git(
        repo_root,
        &[
            "update-ref".to_owned(),
            "HEAD".to_owned(),
            prepared.new_head.clone(),
            prepared.base_head.clone(),
        ],
    )?;
    run_git(
        repo_root,
        &["add".to_owned(), "--".to_owned(), path.to_owned()],
    )?;
    Ok(())
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
        expected_post_action_fork_hash: stored.expected_post_action_fork_hash,
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
mod tests;
