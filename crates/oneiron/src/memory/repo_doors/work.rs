//! `self.code.snapshots.ingest` and `self.code.work.open`, the ref
//! contract the run doors share (CALLS "FIX 6867 run-only ref contract"),
//! and the resolution of a run's own work.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::Path;

use super::{
    NO_PATHS, RepoRunAdmitted, RepoRunAnswer, RepoRunBinding, RepoRunStamp, RepoSnapshotView,
    RepoSnapshotsIngestInput, RepoSnapshotsIngestOutput, RepoWorkOpenInput, RepoWorkOpenOutput,
    RepoWorkView, refusal_error, repo_target,
};
use crate::code_view::{CodeViewSet, ViewReceipt, view_receipt_in_txn};
use crate::codebase::{CodebaseFileEntry, CodebaseSnapshot, RepoRef};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::federation::{RepoAccessIntent, RepoAccessRefusal};
use crate::git_wire::{
    GitOid, GitRefName, GitWire, GitWireRepo, lock_repository, run_bridged_git_argv,
};
use crate::memory::codebase_doors::CodeSnapshotFile;
use crate::memory::{Memory, MemoryResult};
use crate::merge_queue::MergeQueue;
use crate::origin::secret_projection::{RepoSecretAudience, materialize_masked_repo};
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};

/// The queue a run's ref is attached to, read under the repo's coordinator.
pub(crate) struct RepoQueueTarget {
    /// The proven object store.
    pub(crate) repo: GitWireRepo,
    pub(crate) head: String,
    pub(crate) green: String,
}

/// The CALL "FIX 6867 run-only ref contract", one hook: the merge queue is
/// one per object store, not one per ref, so a run's ref names the queue
/// only when it is the full ref the repo's symbolic HEAD is attached to,
/// read under the repo's coordinator with the queue's pointers. A detached
/// HEAD, another ref, a remote pointer, or a store with no queue is
/// [`RepoAccessRefusal::WrongRef`]: no `main`, no `HEAD` and no per-ref queue
/// is guessed. A queue whose merge effect needs recovery, or whose HEAD
/// moved off the queue's head, holds the ref for now: that is the retryable
/// error it raised, never a wrong ref (FIX 6950).
///
/// # Errors
/// The coordinator cannot be taken, or the queue is held for recovery or a
/// moved HEAD ([`Error::ConcurrentWrite`], retryable).
pub(crate) fn resolve_repo_queue_target(
    vault: &Vault,
    repo_ref: &RepoRef,
    git_ref: &str,
) -> Result<std::result::Result<RepoQueueTarget, RepoAccessRefusal>> {
    let Some(repo) = open_local_repo(vault, repo_ref) else {
        return Ok(Err(RepoAccessRefusal::WrongRef));
    };
    let _coordinator = lock_repository(repo.common_dir())?;
    if attached_head(&repo).as_deref() != Some(git_ref) {
        return Ok(Err(RepoAccessRefusal::WrongRef));
    }
    let pointers =
        match MergeQueue::open(vault, repo_ref.clone()).and_then(|queue| queue.pointers()) {
            Ok(pointers) => pointers,
            Err(held @ Error::ConcurrentWrite(_)) => return Err(held),
            Err(_) => return Ok(Err(RepoAccessRefusal::WrongRef)),
        };
    Ok(Ok(RepoQueueTarget {
        repo,
        head: pointers.head,
        green: pointers.green,
    }))
}

/// The commit `git_ref` names now in the object store `repo_ref` names,
/// peeled to a commit: the pin a snapshot door reads at. `None` for a
/// remote pointer, a ref that is not there, or a store that does not read.
pub(super) fn repo_ref_pin(vault: &Vault, repo_ref: &RepoRef, git_ref: &str) -> Option<GitOid> {
    let repo = open_local_repo(vault, repo_ref)?;
    let name = GitRefName::parse_full(git_ref).ok()?;
    let wire = GitWire::new(vault).ok()?;
    let named = wire.read_ref(&repo, &name).ok()??;
    wire.resolve_commit(&repo, named.as_str()).ok()
}

/// The proven object store of a local folder pointer; `None` for a remote
/// pointer or a folder that does not prove.
pub(super) fn open_local_repo(vault: &Vault, repo_ref: &RepoRef) -> Option<GitWireRepo> {
    let RepoRef::LocalFolder { path, .. } = repo_ref else {
        return None;
    };
    GitWire::new(vault)
        .ok()?
        .open_repo(repo_ref.clone(), Path::new(path))
        .ok()
}

/// The full ref the repo's symbolic HEAD is attached to; `None` when HEAD
/// is detached or does not read.
fn attached_head(repo: &GitWireRepo) -> Option<String> {
    let args = ["symbolic-ref", "--quiet", "HEAD"].map(str::to_owned);
    let output = run_bridged_git_argv(repo.repo_root(), &args).ok()?;
    if !output.success {
        return None;
    }
    let name = String::from_utf8(output.stdout).ok()?;
    Some(name.trim_end_matches(['\r', '\n']).to_owned())
}

/// Whether two local folder pointers name one repository folder.
pub(super) fn same_folder(left: &RepoRef, right: &RepoRef) -> bool {
    matches!(
        (left, right),
        (RepoRef::LocalFolder { path: a, .. }, RepoRef::LocalFolder { path: b, .. }) if a == b
    )
}

/// The files of a work, as a run reads them.
pub(super) fn work_view(receipt: &ViewReceipt, stamp: &RepoRunStamp) -> RepoWorkView {
    RepoWorkView {
        work: receipt.view_id,
        repo: stamp.repo,
        git_ref: stamp.git_ref.clone(),
        base_green: stamp.base_green.clone(),
        base_snapshot: bytes_to_hex_lower(&stamp.base_snapshot),
        fork_hash: bytes_to_hex_lower(&receipt.fork_hash),
        files: receipt
            .files
            .iter()
            .map(|(path, hash)| super::RepoWorkFile {
                path: path.clone(),
                content_hash_blake3: bytes_to_hex_lower(hash),
            })
            .collect(),
    }
}

/// A run's own work, admitted: its receipt, its stamp, and the admission it
/// was judged under now.
pub(crate) struct RepoOwnWork {
    pub(crate) receipt: ViewReceipt,
    pub(crate) stamp: RepoRunStamp,
    pub(crate) admitted: RepoRunAdmitted,
}

impl Vault {
    /// The work `work` of the run `binding` binds, admitted in `txn` for
    /// `intent` on `paths` at its repo and ref. A work that is no run's, or
    /// another actor's, executor run's or TASK's, is no membership, so no id
    /// is an existence oracle; this run's work bound under another lease of
    /// its try is a stale lease.
    ///
    /// # Errors
    /// A store, fold or clock failure; never a refusal.
    pub(crate) fn admitted_repo_work_in_txn<S: AsRef<str>>(
        &self,
        txn: &heed::RoTxn<'_>,
        binding: &RepoRunBinding,
        work: EntityId,
        paths: impl IntoIterator<Item = S>,
        intent: RepoAccessIntent,
    ) -> Result<std::result::Result<RepoOwnWork, RepoAccessRefusal>> {
        let Some((receipt, stamp)) = view_receipt_in_txn(self, txn, work)?
            .and_then(|receipt| receipt.run.clone().map(|stamp| (receipt, stamp)))
        else {
            return Ok(Err(RepoAccessRefusal::NoMembership));
        };
        if receipt.actor != binding.actor.entity_ref()
            || stamp.executor_run != binding.executor_run
            || stamp.task != binding.task
            || stamp.work != work
        {
            return Ok(Err(RepoAccessRefusal::NoMembership));
        }
        let target = repo_target(stamp.repo, &stamp.git_ref, paths);
        let admitted = match self.admit_repo_run_in_txn(txn, binding, &target, intent)? {
            Ok(admitted) => admitted,
            Err(refused) => return Ok(Err(refused)),
        };
        if !admitted.holds(&stamp) {
            return Ok(Err(RepoAccessRefusal::StaleLease));
        }
        Ok(Ok(RepoOwnWork {
            receipt,
            stamp,
            admitted,
        }))
    }
}

impl Memory<'_> {
    /// `self.code.snapshots.ingest` for a run: imports the commit the
    /// admitted repo's full ref names now, from the folder the stored anchor
    /// names, through the importer's own writer. Only the paths the Grant
    /// reads reach the snapshot, its blobs and its symbols, and the run is
    /// admitted again in that writer, on every kept path. The snapshot keeps
    /// the anchor's own project key.
    pub fn repo_snapshots_ingest_for_run(
        &self,
        binding: &RepoRunBinding,
        input: RepoSnapshotsIngestInput,
    ) -> MemoryResult<RepoRunAnswer<RepoSnapshotsIngestOutput>> {
        let target = repo_target(input.repo, &input.git_ref, NO_PATHS);
        let admitted = self.repo_run_admit(binding, &target, RepoAccessIntent::Read)?;
        self.repo_lane_reads(binding, &[input.repo])?;
        let membership = &admitted.membership;
        let RepoRef::LocalFolder { path, .. } = &membership.repo_ref else {
            return Err(refusal_error(RepoAccessRefusal::WrongRef));
        };
        let Some(commit) = repo_ref_pin(self.vault, &membership.repo_ref, &input.git_ref) else {
            return Err(refusal_error(RepoAccessRefusal::WrongRef));
        };
        let Some(anchor) = self.vault.get_codebase_snapshot(&input.repo)? else {
            return Err(refusal_error(RepoAccessRefusal::NoMembership));
        };
        // The paths kept are the selection; the final writer admits each of
        // them again, so a Grant narrowed since keeps none it no longer
        // reads (FIX 8799).
        let kept = RefCell::new(Vec::<String>::new());
        let select = |path: &str| {
            let admits = membership.bounds.admits_path(RepoAccessIntent::Read, path);
            if admits {
                kept.borrow_mut().push(path.to_owned());
            }
            admits
        };
        let at = self.vault.store.clock.now_recorded_at();
        let imported = self.vault.ingest_local_repo_for_run(
            anchor.project_id,
            Path::new(path),
            commit.as_str(),
            (TimeRange { start: at, end: at }, at),
            &select,
            |txn| {
                let selected = repo_target(input.repo, &input.git_ref, kept.borrow().iter());
                Ok(
                    match self.vault.admit_repo_run_in_txn(
                        txn,
                        binding,
                        &selected,
                        RepoAccessIntent::Read,
                    )? {
                        Ok(again) if again.same_lease(&admitted) => Ok(()),
                        Ok(_) => Err(RepoAccessRefusal::StaleLease),
                        Err(refused) => Err(refused),
                    },
                )
            },
        )?;
        let imported = imported.map_err(refusal_error)?;
        Ok(RepoRunAnswer {
            rows: vec![input.repo, imported.code_artifact_id],
            output: RepoSnapshotView {
                repo: input.repo,
                git_ref: input.git_ref,
                commit: commit.as_str().to_owned(),
                snapshot: bytes_to_hex_lower(&imported.snapshot.fork_hash),
                artifact: imported.code_artifact_id,
                files: imported.snapshot.files.iter().map(snapshot_file).collect(),
            },
        })
    }

    /// `self.code.work.open` for a run: a fresh private view of the files
    /// the Grant reads, from the immutable tree of the green commit of the
    /// queue the run's ref is attached to. The receipt's own writer admits
    /// the run again, on every selected path, and binds its stamp, under the
    /// view's fresh id: two opens, even by the same agent, are two works.
    pub fn repo_work_open_for_run(
        &self,
        binding: &RepoRunBinding,
        input: RepoWorkOpenInput,
    ) -> MemoryResult<RepoRunAnswer<RepoWorkOpenOutput>> {
        let target = repo_target(input.repo, &input.git_ref, NO_PATHS);
        let admitted = self.repo_run_admit(binding, &target, RepoAccessIntent::Read)?;
        self.repo_lane_reads(binding, &[input.repo])?;
        let membership = &admitted.membership;
        let queue = resolve_repo_queue_target(self.vault, &membership.repo_ref, &input.git_ref)?
            .map_err(refusal_error)?;
        let green = GitOid::parse_hex(queue.green.clone())?;
        let base = self
            .vault
            .capture_repo_snapshot_at_commit(&queue.repo, &green)?;
        let selected: BTreeMap<String, Vec<u8>> = base
            .files
            .into_iter()
            .filter(|(path, _)| membership.bounds.admits_path(RepoAccessIntent::Read, path))
            .collect();
        // A run's work holds the masked copy of each admitted file a repo
        // mark covers (FIX 7608); its stamp keeps the canonical green.
        let selected = materialize_masked_repo(self.vault, selected, &RepoSecretAudience::Masked)?
            .into_contents();
        // The final writer admits every selected path again (FIX 8799).
        let selected_target = repo_target(input.repo, &input.git_ref, selected.keys());
        let entries = selected
            .iter()
            .map(|(path, bytes)| {
                CodebaseFileEntry::new(
                    path.clone(),
                    *blake3::hash(bytes).as_bytes(),
                    bytes.len() as u64,
                )
            })
            .collect();
        let snapshot = CodebaseSnapshot::new(
            input.repo.to_hex(),
            membership.repo_ref.clone(),
            Some(queue.green.clone()),
            entries,
        )?;
        let set = CodeViewSet::open(self.vault)?;
        let opened = set.materialize_tree_for_run(
            binding.actor.entity_ref(),
            snapshot.fork_hash,
            &selected,
            |txn, view| {
                Ok(
                    match self.vault.admit_repo_run_in_txn(
                        txn,
                        binding,
                        &selected_target,
                        RepoAccessIntent::Read,
                    )? {
                        Ok(again) if again.same_lease(&admitted) => Ok(again.stamp(
                            binding,
                            &input.git_ref,
                            &queue.green,
                            base.fork_hash,
                            view,
                        )),
                        Ok(_) => Err(RepoAccessRefusal::StaleLease),
                        Err(refused) => Err(refused),
                    },
                )
            },
        )?;
        let receipt = opened.map_err(refusal_error)?;
        let stamp = receipt
            .run
            .clone()
            .ok_or(Error::InvariantViolation("a run's work lost its stamp"))?;
        Ok(RepoRunAnswer {
            rows: vec![input.repo],
            output: work_view(&receipt, &stamp),
        })
    }
}

/// One manifest entry as the snapshot doors show it.
pub(super) fn snapshot_file(entry: &CodebaseFileEntry) -> CodeSnapshotFile {
    CodeSnapshotFile {
        path: entry.path.clone(),
        content_hash_blake3: bytes_to_hex_lower(&entry.content_hash),
        size_bytes: entry.size_bytes,
        mode: entry.mode,
        projection: None,
    }
}
