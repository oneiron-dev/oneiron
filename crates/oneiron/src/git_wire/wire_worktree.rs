//! Journaled worktree effects: list, prune, add, remove, and crash-journal settlement.

use std::path::{Path, PathBuf};

use super::argv::FrozenGitArgv;
use super::failure::invalid;
use super::record::{
    StoredGitWireRecord, finish_state, hash_field, new_record, receipt_from_stored,
    worktree_record_key,
};
use super::{
    GIT_WIRE_DOMAIN, GitOid, GitWire, GitWireCommitOutcome, GitWireFailureClass, GitWireOperation,
    GitWireReceipt, GitWireRecordState, GitWireRejection, GitWireRepo, GitWireResult,
    lock_repository,
};
use crate::error::Result;

impl GitWire<'_> {
    /// Every worktree registered in this repository.
    pub fn list_worktrees(&self, repo: &GitWireRepo) -> GitWireResult<Vec<PathBuf>> {
        let output = self.run_read(repo, &FrozenGitArgv::worktree_list())?;
        Ok(parse_worktree_listing(&output.stdout))
    }

    /// Whether `path` is registered as a worktree of this repository.
    pub fn worktree_registered(&self, repo: &GitWireRepo, path: &Path) -> GitWireResult<bool> {
        let registered = self.list_worktrees(repo)?;
        Ok(registered.iter().any(|entry| same_path(entry, path)))
    }

    /// Reconciles worktree registration with the filesystem.
    pub fn prune_worktrees(&self, repo: &GitWireRepo) -> GitWireResult<()> {
        let _guard = lock_repository(&repo.common_dir)?;
        self.run_mutation(repo, &FrozenGitArgv::worktree_prune())?;
        Ok(())
    }

    /// Registers a worktree materializing exactly `commit`, journaling the
    /// intent first so a crash between git and the record is recoverable.
    pub fn add_worktree(
        &self,
        repo: &GitWireRepo,
        path: &Path,
        commit: &GitOid,
        now: u64,
    ) -> GitWireResult<GitWireReceipt> {
        let argv = FrozenGitArgv::worktree_add(path, commit)?;
        self.run_worktree_effect(repo, GitWireOperation::WorktreeAdd, path, &argv, now)
    }

    /// Removes a registered worktree. Returns `Ok(None)` when the path is not
    /// registered, so nothing was owned and nothing was removed.
    pub fn remove_worktree(
        &self,
        repo: &GitWireRepo,
        path: &Path,
        now: u64,
    ) -> GitWireResult<Option<GitWireReceipt>> {
        let _guard = lock_repository(&repo.common_dir)?;
        if !self.worktree_registered(repo, path)? {
            return Ok(None);
        }
        let argv = FrozenGitArgv::worktree_remove(path)?;
        let receipt =
            self.run_worktree_effect(repo, GitWireOperation::WorktreeRemove, path, &argv, now)?;
        Ok(Some(receipt))
    }

    /// Journals the intent, performs the effect, reconciles registration, and
    /// then clears the record.
    ///
    /// A worktree effect has no replay value — it is a filesystem state, not a
    /// claim — so the durable row exists purely as a crash journal. A crash
    /// between git and the clear leaves a prepared row that recovery resolves
    /// by re-observing registration.
    fn run_worktree_effect(
        &self,
        repo: &GitWireRepo,
        operation: GitWireOperation,
        path: &Path,
        argv: &FrozenGitArgv,
        now: u64,
    ) -> Result<GitWireReceipt> {
        let _guard = lock_repository(&repo.common_dir)?;
        let scope = worktree_scope(path);
        let key = worktree_record_key(repo.identity(), operation, &scope);
        let mut record = new_record(repo, key, operation, &[], &[], now);
        record.worktree_scope = Some(scope);
        self.put_record(repo, &record)?;
        self.run_mutation(repo, argv)?;
        self.run_mutation(repo, &FrozenGitArgv::worktree_prune())?;
        self.drop_record(repo, &key)?;
        receipt_from_stored(&finish_state(
            record,
            GitWireRecordState::Applied,
            Vec::new(),
            now,
        ))
    }

    /// Resolves a prepared worktree record by re-observing registration. The
    /// path is never stored: the record carries a scope hash, and recovery
    /// matches it against the paths git currently reports.
    pub(super) fn finish_worktree_record(
        &self,
        repo: &GitWireRepo,
        record: StoredGitWireRecord,
        now: u64,
    ) -> Result<GitWireCommitOutcome> {
        let operation = GitWireOperation::parse(&record.operation)?;
        let scope = record
            .worktree_scope
            .ok_or_else(|| invalid("git wire worktree record has no scope"))?;
        let registered = self
            .list_worktrees(repo)?
            .into_iter()
            .find(|path| worktree_scope(path) == scope);
        let resolved = match (operation, registered) {
            (GitWireOperation::WorktreeRemove, Some(path)) => {
                let argv = FrozenGitArgv::worktree_remove(&path)?;
                self.run_mutation(repo, &argv)?;
                true
            }
            (GitWireOperation::WorktreeAdd, Some(_))
            | (GitWireOperation::WorktreeRemove, None)
            | (GitWireOperation::WorktreePrune, _) => true,
            (_, _) => false,
        };
        self.settle_worktree(repo, record, resolved, now)
    }

    fn settle_worktree(
        &self,
        repo: &GitWireRepo,
        record: StoredGitWireRecord,
        resolved: bool,
        now: u64,
    ) -> Result<GitWireCommitOutcome> {
        self.run_mutation(repo, &FrozenGitArgv::worktree_prune())?;
        self.drop_record(repo, &record.record_key)?;
        let state = if resolved {
            GitWireRecordState::Applied
        } else {
            GitWireRecordState::Failed
        };
        let mut settled = finish_state(record, state, Vec::new(), now);
        if !resolved {
            settled.failure = Some(GitWireFailureClass::Unknown.as_str().to_owned());
        }
        let receipt = receipt_from_stored(&settled)?;
        if resolved {
            return Ok(GitWireCommitOutcome::Applied(receipt));
        }
        Ok(GitWireCommitOutcome::Rejected {
            receipt,
            reason: GitWireRejection::EffectUnconfirmed,
        })
    }
}

fn parse_worktree_listing(stdout: &[u8]) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for field in stdout.split(|byte| *byte == 0) {
        let Some(raw) = field.strip_prefix(b"worktree ") else {
            continue;
        };
        let Ok(text) = std::str::from_utf8(raw) else {
            continue;
        };
        paths.push(PathBuf::from(text));
    }
    paths
}

fn same_path(left: &Path, right: &Path) -> bool {
    left == right || normalized_path(left) == normalized_path(right)
}

/// A path normalized as far as the filesystem allows.
///
/// A worktree that has just been removed no longer resolves, so falling back to
/// the resolved parent keeps a removed handle comparable with the path git
/// reported for it.
fn normalized_path(path: &Path) -> PathBuf {
    if let Ok(resolved) = path.canonicalize() {
        return resolved;
    }
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => match parent.canonicalize() {
            Ok(parent) => parent.join(name),
            Err(_) => path.to_path_buf(),
        },
        _ => path.to_path_buf(),
    }
}

pub(super) fn worktree_scope(path: &Path) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, GIT_WIRE_DOMAIN);
    hash_field(&mut hasher, b"worktree-scope");
    hash_field(
        &mut hasher,
        normalized_path(path).as_os_str().as_encoded_bytes(),
    );
    *hasher.finalize().as_bytes()
}
