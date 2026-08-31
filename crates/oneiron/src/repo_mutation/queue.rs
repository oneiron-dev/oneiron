use std::path::{Path, PathBuf};

use crate::Vault;
use crate::codebase::RepoRef;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{GitWire, lock_repository};
#[cfg(test)]
use crate::git_wire::{GIT_WIRE_REPO_LOCK_FILE_NAME, GitWireRepoGuard};

use super::conflict::{record_repo_conflict, resolve_repo_conflict_file, tree_hash_for_ref};
use super::git::{
    canonical_repo_ref_for_root, git_commit_object_available, git_common_dir,
    resolve_mutable_repo_root, validate_base_ref, validate_commit_message,
    validate_git_ref_label, validate_relative_repo_path, validate_worktree_path,
};
use super::oplog::{
    REPO_MUTATION_OPLOG_SCHEMA_VERSION, StoredPreparedConflictResolution,
    StoredRepoMutationOplogEntry, decode_stored_oplog_entry, encode_oplog_entry,
    public_oplog_entry, repo_mutation_oplog_key, repo_mutation_repo_key_hash,
    repo_mutation_seq_key, repo_mutation_snapshot_key,
};
use super::snapshot::{
    StoredRepoSnapshot, StoredRepoSnapshotEntry, StoredRepoSnapshotEntryKind,
    capture_repo_snapshot, decode_snapshot, encode_snapshot, restore_repo_snapshot,
};
use super::support::{hex_bytes, now_millis, sha256_bytes, truncate_failure};
use super::trailer::{commit_message_with_provenance_trailer, validate_repo_provenance_request};
use super::types::{
    RepoForkHash, RepoMutationOperation, RepoMutationOplogEntry, RepoMutationOutcome,
    RepoMutationRequest, RepoMutationStatus,
};
use super::worktree::{
    apply_prepared_commit_file, prepare_commit_file_through_queue_worktree,
    prune_queue_owned_worktrees, remove_queue_worktree,
};

/// The repo-mutation writer lock is GitWire's repository coordinator: one
/// advisory lock file in the canonical git common directory, shared by every
/// GitWire ref/worktree effect and every queued mutation, so the two clusters
/// serialize against each other across threads and processes.
#[cfg(test)]
pub(super) const REPO_MUTATION_LOCK_FILE_NAME: &str = GIT_WIRE_REPO_LOCK_FILE_NAME;

#[cfg(test)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum RepoMutationCrashPoint {
    #[default]
    None,
    AfterPreparedBeforeAction,
    AfterActionBeforeApplied,
}

#[cfg(test)]
thread_local! {
    pub(super) static INJECT_REPO_MUTATION_CRASH: std::cell::Cell<RepoMutationCrashPoint> =
        const { std::cell::Cell::new(RepoMutationCrashPoint::None) };
}

/// The queue's hold on the repository writer lock. Production callers take
/// [`lock_repository`] directly; this wrapper keeps the queue's own lock
/// contract nameable.
#[cfg(test)]
pub(super) struct RepoMutationFileLock(#[allow(dead_code)] GitWireRepoGuard);

#[derive(Debug, Clone)]
pub(super) struct PreparedRepoMutation {
    pub(super) repo_key_hash: String,
    pub(super) seq: u64,
}

#[derive(Debug)]
pub(super) struct PreparedRepoMutationAction {
    pub(super) oplog: PreparedRepoMutation,
    pub(super) execution: PreparedRepoMutationExecution,
}

#[derive(Debug)]
pub(super) enum PreparedRepoMutationExecution {
    Direct,
    CommitFile(PreparedCommitFile),
    ResolveConflictFile {
        commit: PreparedCommitFile,
        recovery: PreparedConflictResolution,
    },
}

#[derive(Debug)]
pub(super) struct PreparedCommitFile {
    pub(super) worktree_path: PathBuf,
    pub(super) base_head: String,
    pub(super) new_head: String,
}

#[derive(Debug, Clone)]
pub(super) struct PreparedConflictResolution {
    pub(super) resolution_claim_id: EntityId,
    pub(super) branch_subject: EntityId,
    pub(super) open_conflict_claim_id: EntityId,
    pub(super) branch_name: String,
    pub(super) path: String,
    pub(super) resolved_tree: String,
}

impl PreparedRepoMutationExecution {
    pub(super) fn commit_file(&self) -> Result<&PreparedCommitFile> {
        match self {
            Self::CommitFile(prepared) => Ok(prepared),
            Self::ResolveConflictFile { commit, .. } => Ok(commit),
            Self::Direct => Err(Error::InvariantViolation(
                "commit-producing repo mutation missing prepared commit",
            )),
        }
    }

    pub(super) fn conflict_resolution(&self) -> Result<&PreparedConflictResolution> {
        let Self::ResolveConflictFile { recovery, .. } = self else {
            return Err(Error::InvariantViolation(
                "conflict resolution missing prepared recovery intent",
            ));
        };
        Ok(recovery)
    }

    pub(super) fn cleanup(&self, repo_root: &Path) -> Result<()> {
        match self {
            Self::Direct => Ok(()),
            Self::CommitFile(prepared) => remove_queue_worktree(repo_root, &prepared.worktree_path),
            Self::ResolveConflictFile { commit, .. } => {
                remove_queue_worktree(repo_root, &commit.worktree_path)
            }
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
        let _guard = lock_repository(&common_dir)?;
        let _ = prune_queue_owned_worktrees(&repo_root);

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

    /// Stages the mutation's git objects, then records the write-ahead row.
    ///
    /// RC6 two-phase order, in this function and nowhere else: every
    /// object-producing git call runs in `prepare_repo_mutation_execution`
    /// *before* the LMDB write transaction below exists, the staged commit is
    /// verified to be durable in the repository, and only then does the
    /// transactional phase write rows. The ref advance those rows authorise
    /// happens after the commit, in `execute_repo_mutation`.
    pub(super) fn prepare_repo_mutation(
        &self,
        repo_ref: &RepoRef,
        request: &RepoMutationRequest,
        repo_root: &Path,
    ) -> Result<PreparedRepoMutationAction> {
        let (fork_hash, snapshot_bytes) = capture_repo_snapshot(repo_root)?;
        let pre_action_snapshot = decode_snapshot(&snapshot_bytes)?;
        let execution = match prepare_repo_mutation_execution(repo_root, request) {
            Ok(execution) => execution,
            Err(error) => {
                self.record_failed_repo_mutation_preparation(
                    repo_ref,
                    request,
                    fork_hash,
                    &snapshot_bytes,
                    &error,
                )?;
                return Err(error);
            }
        };
        let prepared = (|| -> Result<PreparedRepoMutation> {
            require_staged_objects_available(repo_root, &execution)?;
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
                prepared_conflict_resolution: match &execution {
                    PreparedRepoMutationExecution::ResolveConflictFile { recovery, .. } => {
                        Some(StoredPreparedConflictResolution::from(recovery))
                    }
                    PreparedRepoMutationExecution::Direct
                    | PreparedRepoMutationExecution::CommitFile(_) => None,
                },
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

    fn record_failed_repo_mutation_preparation(
        &self,
        repo_ref: &RepoRef,
        request: &RepoMutationRequest,
        fork_hash: RepoForkHash,
        snapshot_bytes: &[u8],
        error: &Error,
    ) -> Result<()> {
        let repo_key_hash = repo_mutation_repo_key_hash(repo_ref);
        let timestamp = now_millis();
        let mut wtxn = self.store.env.write_txn()?;
        store_snapshot_if_absent(self, &mut wtxn, fork_hash, snapshot_bytes)?;
        let seq = allocate_next_repo_mutation_seq(self, &mut wtxn, &repo_key_hash)?;
        let stored = StoredRepoMutationOplogEntry {
            schema_version: REPO_MUTATION_OPLOG_SCHEMA_VERSION,
            repo_ref: repo_ref.canonical(),
            seq,
            operation_kind: request.operation.kind().to_owned(),
            operation_subject: Some(operation_subject(&request.operation)),
            actor_id: request.actor_id.map(|id| *id.as_bytes()),
            session_id: request.session_id.map(|id| *id.as_bytes()),
            started_at_ms: timestamp,
            finished_at_ms: Some(timestamp),
            pre_action_fork_hash: fork_hash,
            expected_post_action_fork_hash: None,
            prepared_conflict_resolution: None,
            status: RepoMutationStatus::Failed.as_str().to_owned(),
            failure: Some(truncate_failure(&error.to_string())),
        };
        let encoded = encode_oplog_entry(&stored)?;
        self.store.vault_meta.put(
            &mut wtxn,
            &repo_mutation_oplog_key(&repo_key_hash, seq),
            &encoded,
        )?;
        wtxn.commit()?;
        Ok(())
    }

    pub(super) fn finish_repo_mutation(
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
        let mut stored = decode_stored_oplog_entry(&raw)?;
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
        } => Some((path.as_str(), content.as_slice(), message.as_str(), None)),
        RepoMutationOperation::ResolveConflictFile {
            branch_subject,
            open_conflict_claim_id,
            branch_name,
            path,
            content,
            message,
            ..
        } => Some((
            path.as_str(),
            content.as_slice(),
            message.as_str(),
            Some((
                *branch_subject,
                *open_conflict_claim_id,
                branch_name.as_str(),
            )),
        )),
        _ => None,
    };
    let Some((path, content, message, conflict)) = commit else {
        return Ok(PreparedRepoMutationExecution::Direct);
    };
    let message = commit_message_with_provenance_trailer(message, request.provenance_claim_id)?;
    let commit = prepare_commit_file_through_queue_worktree(repo_root, path, content, &message)?;
    let Some((branch_subject, open_conflict_claim_id, branch_name)) = conflict else {
        return Ok(PreparedRepoMutationExecution::CommitFile(commit));
    };
    let resolved_tree = match tree_hash_for_ref(repo_root, &commit.new_head) {
        Ok(tree) => tree,
        Err(error) => {
            let _ = remove_queue_worktree(repo_root, &commit.worktree_path);
            return Err(error);
        }
    };
    let recovery = PreparedConflictResolution {
        resolution_claim_id: EntityId::now(),
        branch_subject,
        open_conflict_claim_id,
        branch_name: branch_name.to_owned(),
        path: path.to_owned(),
        resolved_tree,
    };
    Ok(PreparedRepoMutationExecution::ResolveConflictFile { commit, recovery })
}

/// Refuses to write a prepared row whose staged object set is not durable.
///
/// The object-producing phase has already finished when this runs, so a missing
/// commit object means the staging did not survive; failing here keeps the
/// write-ahead row — and therefore the ref advance it authorises — from ever
/// naming an unavailable object set.
fn require_staged_objects_available(
    repo_root: &Path,
    execution: &PreparedRepoMutationExecution,
) -> Result<()> {
    if matches!(execution, PreparedRepoMutationExecution::Direct) {
        return Ok(());
    }
    let commit = execution.commit_file()?;
    if git_commit_object_available(repo_root, &commit.new_head, &commit.base_head)? {
        return Ok(());
    }
    Err(Error::RepoMutationFailed(
        "staged commit object is unavailable; refusing to prepare a ref advance".to_owned(),
    ))
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

pub(super) fn execute_repo_mutation(
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
        // Worktree effects are the queue's other irreversible git effect, so
        // they run through the same bound GitWire protocol as every ref move:
        // a durable intent is journaled before git, the base revision is pinned
        // to an exact commit instead of a moving name, and registration is
        // reconciled afterwards.
        RepoMutationOperation::CreateWorktree {
            worktree_path,
            base_ref,
        } => {
            validate_worktree_path(worktree_path)?;
            validate_base_ref(base_ref)?;
            let wire = GitWire::new(vault)?;
            let repo = wire.open_repo(repo_ref.clone(), repo_root)?;
            let commit = wire.resolve_commit(&repo, base_ref)?;
            wire.add_worktree(&repo, worktree_path, &commit, now_millis())?;
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
            let wire = GitWire::new(vault)?;
            let repo = wire.open_repo(repo_ref.clone(), repo_root)?;
            let removed = wire.remove_worktree(&repo, worktree_path, now_millis())?;
            if removed.is_none() {
                return Err(Error::RepoMutationFailed(
                    "worktree is not registered with this repository".to_owned(),
                ));
            }
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
                execution.conflict_resolution()?,
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
            let bytes: [u8; 8] = bytes.as_ref().try_into().map_err(|_| {
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

#[cfg(test)]
pub(super) fn repo_mutation_file_lock(git_common_dir: &Path) -> Result<RepoMutationFileLock> {
    Ok(RepoMutationFileLock(lock_repository(git_common_dir)?))
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
