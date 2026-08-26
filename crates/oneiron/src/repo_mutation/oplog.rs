use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::codebase::RepoRef;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::conflict::finish_repo_conflict_resolution;
use super::git::{
    canonical_repo_ref_for_root, git_common_dir, resolve_mutable_repo_root, run_git,
    validate_relative_repo_path,
};
use super::queue::{
    PreparedConflictResolution, PreparedRepoMutation, execute_repo_mutation, repo_lock_key,
    repo_mutation_file_lock, repo_mutation_lock,
};
use super::snapshot::capture_repo_snapshot;
use super::support::{hex_bytes, now_millis, sha256_bytes, truncate_failure};
use super::types::{
    RepoForkHash, RepoMutationOperation, RepoMutationOplogEntry, RepoMutationOutcome,
    RepoMutationRequest, RepoMutationStatus,
};
use super::worktree::prune_queue_owned_worktrees;

pub const REPO_MUTATION_OPLOG_SCHEMA_VERSION: u8 = 1;

const REPO_MUTATION_SEQ_KEY_PREFIX: &[u8] = b"repo_mutation:seq:v1:";
const REPO_MUTATION_OPLOG_KEY_PREFIX: &[u8] = b"repo_mutation:oplog:v1:";
const REPO_MUTATION_SNAPSHOT_KEY_PREFIX: &[u8] = b"repo_mutation:snapshot:v1:";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredPreparedConflictResolution {
    pub(super) resolution_claim_id: [u8; 16],
    pub(super) branch_subject: [u8; 16],
    pub(super) open_conflict_claim_id: [u8; 16],
    pub(super) branch_name: String,
    pub(super) path: String,
    pub(super) resolved_tree: String,
}

impl From<&PreparedConflictResolution> for StoredPreparedConflictResolution {
    fn from(value: &PreparedConflictResolution) -> Self {
        Self {
            resolution_claim_id: *value.resolution_claim_id.as_bytes(),
            branch_subject: *value.branch_subject.as_bytes(),
            open_conflict_claim_id: *value.open_conflict_claim_id.as_bytes(),
            branch_name: value.branch_name.clone(),
            path: value.path.clone(),
            resolved_tree: value.resolved_tree.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredRepoMutationOplogEntry {
    pub(super) schema_version: u8,
    pub(super) repo_ref: String,
    pub(super) seq: u64,
    pub(super) operation_kind: String,
    pub(super) operation_subject: Option<String>,
    pub(super) actor_id: Option<[u8; 16]>,
    pub(super) session_id: Option<[u8; 16]>,
    pub(super) started_at_ms: u64,
    pub(super) finished_at_ms: Option<u64>,
    pub(super) pre_action_fork_hash: RepoForkHash,
    #[serde(default)]
    pub(super) expected_post_action_fork_hash: Option<RepoForkHash>,
    #[serde(default)]
    pub(super) prepared_conflict_resolution: Option<StoredPreparedConflictResolution>,
    pub(super) status: String,
    pub(super) failure: Option<String>,
}

impl Vault {
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
        let _ = prune_queue_owned_worktrees(&repo_root);
        self.recover_prepared_repo_mutations_locked(&canonical, &repo_root)
    }

    /// Reads the durable oplog for a repo in sequence order.
    pub fn repo_mutation_oplog(&self, repo_ref: &RepoRef) -> Result<Vec<RepoMutationOplogEntry>> {
        let repo_root = resolve_mutable_repo_root(repo_ref)?;
        let canonical = canonical_repo_ref_for_root(repo_ref, &repo_root)?;
        self.repo_mutation_oplog_for_canonical(&canonical)
    }

    pub(super) fn repo_mutation_oplog_for_canonical(
        &self,
        repo_ref: &RepoRef,
    ) -> Result<Vec<RepoMutationOplogEntry>> {
        self.stored_repo_mutation_oplog_for_canonical(repo_ref)?
            .into_iter()
            .map(public_oplog_entry)
            .collect()
    }

    fn stored_repo_mutation_oplog_for_canonical(
        &self,
        repo_ref: &RepoRef,
    ) -> Result<Vec<StoredRepoMutationOplogEntry>> {
        let repo_key_hash = repo_mutation_repo_key_hash(repo_ref);
        let prefix = repo_mutation_oplog_prefix(&repo_key_hash);
        let rtxn = self.store.env.read_txn()?;
        let mut entries = Vec::new();
        for row in self.store.vault_meta.prefix_iter(&rtxn, &prefix)? {
            let (_, bytes) = row?;
            entries.push(decode_stored_oplog_entry(&bytes)?);
        }
        entries.sort_by_key(|entry| entry.seq);
        Ok(entries)
    }

    pub(super) fn recover_prepared_repo_mutations_locked(
        &self,
        repo_ref: &RepoRef,
        repo_root: &Path,
    ) -> Result<Vec<RepoMutationOutcome>> {
        let prepared_entries = self
            .stored_repo_mutation_oplog_for_canonical(repo_ref)?
            .into_iter()
            .filter(|entry| entry.status == RepoMutationStatus::Prepared.as_str())
            .collect::<Vec<_>>();
        let mut outcomes = Vec::new();
        for stored in prepared_entries {
            let recovery_intent = stored.prepared_conflict_resolution.clone();
            let stale = public_oplog_entry(stored)?;
            let (actual_fork_hash, _) = capture_repo_snapshot(repo_root)?;
            if stale.operation_kind == "resolve_conflict_file"
                && recovery_intent.is_none()
                && actual_fork_hash != stale.pre_action_fork_hash
            {
                let entry = self.finish_repo_mutation(
                    &PreparedRepoMutation {
                        repo_key_hash: repo_mutation_repo_key_hash(repo_ref),
                        seq: stale.seq,
                    },
                    RepoMutationStatus::Failed,
                    Some(
                        "prepared conflict resolution missing claim recovery intent; repo left untouched"
                            .into(),
                    ),
                    now_millis(),
                )?;
                outcomes.push(RepoMutationOutcome {
                    entry,
                    repo_conflict_claim_id: None,
                });
                continue;
            }
            if stale
                .expected_post_action_fork_hash
                .is_some_and(|expected| {
                    expected != stale.pre_action_fork_hash && actual_fork_hash == expected
                })
            {
                let repo_conflict_claim_id = finish_repo_mutation_roll_forward(
                    self,
                    repo_ref,
                    repo_root,
                    &stale,
                    recovery_intent.as_ref(),
                )?;
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
                    repo_conflict_claim_id,
                });
                continue;
            }

            if stale.expected_post_action_fork_hash.is_none()
                && actual_fork_hash != stale.pre_action_fork_hash
            {
                let entry = self.finish_repo_mutation(
                    &PreparedRepoMutation {
                        repo_key_hash: repo_mutation_repo_key_hash(repo_ref),
                        seq: stale.seq,
                    },
                    RepoMutationStatus::Failed,
                    Some(
                        "legacy prepared row missing expected post-state; repo left untouched"
                            .into(),
                    ),
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
}

fn finish_repo_mutation_roll_forward(
    vault: &Vault,
    repo_ref: &RepoRef,
    repo_root: &Path,
    stale: &RepoMutationOplogEntry,
    stored_resolution: Option<&StoredPreparedConflictResolution>,
) -> Result<Option<EntityId>> {
    if matches!(
        stale.operation_kind.as_str(),
        "commit_file" | "resolve_conflict_file"
    ) {
        let path = stale
            .operation_subject
            .as_deref()
            .ok_or(Error::InvalidRepoMutationRecord(
                "prepared commit mutation is missing its path",
            ))?;
        validate_relative_repo_path(path)?;
        run_git(
            repo_root,
            &["add".to_owned(), "--".to_owned(), path.to_owned()],
        )?;
    }

    if stale.operation_kind != "resolve_conflict_file" {
        return Ok(None);
    }
    let stored = stored_resolution.ok_or(Error::InvalidRepoMutationRecord(
        "prepared conflict resolution is missing recovery intent",
    ))?;
    let prepared = PreparedConflictResolution {
        resolution_claim_id: EntityId::from_bytes(stored.resolution_claim_id).map_err(|_| {
            Error::InvalidRepoMutationRecord("invalid prepared resolution claim id")
        })?,
        branch_subject: EntityId::from_bytes(stored.branch_subject).map_err(|_| {
            Error::InvalidRepoMutationRecord("invalid prepared resolution branch subject")
        })?,
        open_conflict_claim_id: EntityId::from_bytes(stored.open_conflict_claim_id).map_err(
            |_| Error::InvalidRepoMutationRecord("invalid prepared open conflict claim id"),
        )?,
        branch_name: stored.branch_name.clone(),
        path: stored.path.clone(),
        resolved_tree: stored.resolved_tree.clone(),
    };
    finish_repo_conflict_resolution(vault, repo_ref, repo_root, &prepared).map(Some)
}

pub(super) fn public_oplog_entry(
    stored: StoredRepoMutationOplogEntry,
) -> Result<RepoMutationOplogEntry> {
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

pub(super) fn encode_oplog_entry(entry: &StoredRepoMutationOplogEntry) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(entry)
        .map_err(|_| Error::InvariantViolation("repo mutation oplog encode failed"))
}

pub(super) fn decode_stored_oplog_entry(bytes: &[u8]) -> Result<StoredRepoMutationOplogEntry> {
    rmp_serde::from_slice(bytes)
        .map_err(|_| Error::InvalidRepoMutationRecord("repo mutation oplog is not MessagePack"))
}

fn repo_key_hash(repo_key: &str) -> String {
    hex_bytes(&sha256_bytes(repo_key.as_bytes()))
}

pub(super) fn repo_mutation_repo_key_hash(repo_ref: &RepoRef) -> String {
    repo_key_hash(&repo_mutation_repo_key(repo_ref))
}

pub(super) fn repo_mutation_repo_key(repo_ref: &RepoRef) -> String {
    match repo_ref {
        RepoRef::LocalFolder { path, .. } => format!("local:{path}"),
        RepoRef::GitHubAtCommit { .. } => repo_ref.canonical(),
    }
}

pub(super) fn repo_mutation_seq_key(repo_key_hash: &str) -> Vec<u8> {
    prefixed_key(REPO_MUTATION_SEQ_KEY_PREFIX, repo_key_hash)
}

pub(super) fn repo_mutation_snapshot_key(fork_hash: RepoForkHash) -> Vec<u8> {
    prefixed_key(REPO_MUTATION_SNAPSHOT_KEY_PREFIX, &hex_bytes(&fork_hash))
}

fn repo_mutation_oplog_prefix(repo_key_hash: &str) -> Vec<u8> {
    prefixed_key(REPO_MUTATION_OPLOG_KEY_PREFIX, repo_key_hash)
}

pub(super) fn repo_mutation_oplog_key(repo_key_hash: &str, seq: u64) -> Vec<u8> {
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
