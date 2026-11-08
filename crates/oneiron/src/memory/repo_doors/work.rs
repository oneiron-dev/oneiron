//! `self.code.snapshots.ingest` and `self.code.work.open`, the ref
//! contract the run doors share (CALLS "FIX 6867 run-only ref contract"),
//! and the resolution of a run's own work.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::Path;

use super::{
    NO_PATHS, RepoRunAdmitted, RepoRunAnswer, RepoRunBinding, RepoRunSelection, RepoRunStamp,
    RepoSnapshotView, RepoSnapshotsIngestInput, RepoSnapshotsIngestOutput, RepoWorkOpenInput,
    RepoWorkOpenOutput, RepoWorkView, refusal_error, repo_target,
};
use crate::code_view::{CodeViewSet, ViewReceipt, view_receipt_in_txn};
use crate::codebase::{CodebaseFileEntry, CodebaseSnapshot, RepoRef};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::git_wire::{
    GitOid, GitRefName, GitWire, GitWireRepo, lock_repository, run_bridged_git_argv,
};
use crate::memory::codebase_doors::CodeSnapshotFile;
use crate::memory::{Memory, MemoryResult};
use crate::merge_queue::MergeQueue;
use crate::origin::secret_projection::{RepoSecretAudience, materialize_masked_repo};
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};
use oneiron_authority::federation::{RepoAccessIntent, RepoAccessRefusal};

/// The queue a run's ref is attached to, read under the repo's coordinator.
pub(crate) struct RepoQueueTarget<'v> {
    pub(crate) queue: MergeQueue<'v>,
    pub(crate) head: String,
    pub(crate) green: String,
}

/// The CALL "FIX 6867 run-only ref contract", one hook: the merge queue is
/// one per object store, not one per ref, so a run's ref names the queue
/// only when it is the full ref the repo's symbolic HEAD is attached to,
/// or a served queue's frozen import ref. Both are read under the repo's
/// coordinator with the queue's pointers. A native detached HEAD, another
/// ref, a remote pointer, or a store with no queue is
/// [`RepoAccessRefusal::WrongRef`]: no `main`, no `HEAD` and no per-ref queue
/// is guessed. A queue whose merge effect needs recovery, or whose HEAD
/// moved off the queue's head, holds the ref for now: that is the retryable
/// error it raised, never a wrong ref (FIX 6950).
///
/// # Errors
/// The coordinator cannot be taken, or the queue is held for recovery or a
/// moved HEAD ([`Error::ConcurrentWrite`], retryable).
pub(crate) fn resolve_repo_queue_target<'v>(
    vault: &'v Vault,
    anchor: EntityId,
    repo_ref: &RepoRef,
    git_ref: &str,
) -> Result<std::result::Result<RepoQueueTarget<'v>, RepoAccessRefusal>> {
    let (queue, _coordinator) = match vault.open_served_queue_for_artifact(anchor, repo_ref)? {
        Some((queue, _, frozen_ref)) => {
            let coordinator = lock_repository(queue.repository().common_dir())?;
            if frozen_ref != git_ref {
                return Ok(Err(RepoAccessRefusal::WrongRef));
            }
            (queue, coordinator)
        }
        None => {
            let Some(repo) = open_local_repo(vault, repo_ref) else {
                return Ok(Err(RepoAccessRefusal::WrongRef));
            };
            let coordinator = lock_repository(repo.common_dir())?;
            if attached_head(&repo).as_deref() != Some(git_ref) {
                return Ok(Err(RepoAccessRefusal::WrongRef));
            }
            let queue = match MergeQueue::open(vault, repo_ref.clone()) {
                Ok(queue) => queue,
                Err(held @ Error::ConcurrentWrite(_)) => return Err(held),
                Err(_) => return Ok(Err(RepoAccessRefusal::WrongRef)),
            };
            (queue, coordinator)
        }
    };
    let pointers = match queue.pointers() {
        Ok(pointers) => pointers,
        Err(held @ Error::ConcurrentWrite(_)) => return Err(held),
        Err(_) => return Ok(Err(RepoAccessRefusal::WrongRef)),
    };
    Ok(Ok(RepoQueueTarget {
        queue,
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
                projection: receipt.projections.get(path).cloned(),
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
    /// the anchor's own project key, a registered repository's its PROJECT,
    /// and belongs to the anchor (FIX 4299).
    pub fn repo_snapshots_ingest_for_run(
        &self,
        binding: &RepoRunBinding,
        input: RepoSnapshotsIngestInput,
    ) -> MemoryResult<RepoRunAnswer<RepoSnapshotsIngestOutput>> {
        self.repo_snapshots_ingest_for_run_selected(binding, input, None)
    }

    pub(crate) fn repo_snapshots_ingest_for_run_selected(
        &self,
        binding: &RepoRunBinding,
        input: RepoSnapshotsIngestInput,
        selection: Option<RepoRunSelection>,
    ) -> MemoryResult<RepoRunAnswer<RepoSnapshotsIngestOutput>> {
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        let (selected, portable_hit, admission) = self.vault.admit_repo_run_with_portable_in_txn(
            &txn,
            binding,
            input.repo,
            input.portable_repo.as_ref(),
            &input.git_ref,
            NO_PATHS,
            RepoAccessIntent::Read,
        )?;
        drop(txn);
        let admitted = admission.map_err(refusal_error)?;
        if selection.is_some_and(|gate| gate.repo != selected || gate.portable_hit != portable_hit)
        {
            return Err(Error::ConcurrentWrite("the run's gated repo selection changed").into());
        }
        self.repo_lane_reads(binding, &[selected])?;
        let membership = &admitted.membership;
        let RepoRef::LocalFolder { path, .. } = &membership.repo_ref else {
            return Err(refusal_error(RepoAccessRefusal::WrongRef));
        };
        let Some(commit) = repo_ref_pin(self.vault, &membership.repo_ref, &input.git_ref) else {
            return Err(refusal_error(RepoAccessRefusal::WrongRef));
        };
        let project_id = match self.vault.get_codebase_snapshot(&selected)? {
            Some(anchor) => anchor.project_id,
            None if self.vault.is_registered_repository(selected)? => {
                membership.bounds.project.to_hex()
            }
            None => return Err(refusal_error(RepoAccessRefusal::NoMembership)),
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
            project_id,
            Path::new(path),
            commit.as_str(),
            (TimeRange { start: at, end: at }, at),
            crate::codebase::CaptureRepository {
                anchor: selected,
                project: None,
            },
            &select,
            |txn| {
                let (selected_again, hit_again, admission) =
                    self.vault.admit_repo_run_with_portable_in_txn(
                        txn,
                        binding,
                        input.repo,
                        input.portable_repo.as_ref(),
                        &input.git_ref,
                        kept.borrow().iter(),
                        RepoAccessIntent::Read,
                    )?;
                if selected_again != selected || hit_again != portable_hit {
                    return Err(Error::ConcurrentWrite(
                        "the run's repo ingest selection changed",
                    ));
                }
                Ok(match admission {
                    Ok(again) if again.same_lease(&admitted) => Ok(()),
                    Ok(_) => Err(RepoAccessRefusal::StaleLease),
                    Err(refused) => Err(refused),
                })
            },
        )?;
        let imported = imported.map_err(refusal_error)?;
        Ok(RepoRunAnswer {
            rows: vec![selected, imported.code_artifact_id],
            output: RepoSnapshotView {
                repo: selected,
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
        self.repo_work_open_for_run_selected(binding, input, None)
    }

    pub(crate) fn repo_work_open_for_run_selected(
        &self,
        binding: &RepoRunBinding,
        input: RepoWorkOpenInput,
        selection: Option<RepoRunSelection>,
    ) -> MemoryResult<RepoRunAnswer<RepoWorkOpenOutput>> {
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        let (selected_repo, portable_hit, admission) =
            self.vault.admit_repo_run_with_portable_in_txn(
                &txn,
                binding,
                input.repo,
                input.portable_repo.as_ref(),
                &input.git_ref,
                NO_PATHS,
                RepoAccessIntent::Read,
            )?;
        drop(txn);
        let admitted = admission.map_err(refusal_error)?;
        if selection
            .is_some_and(|gate| gate.repo != selected_repo || gate.portable_hit != portable_hit)
        {
            return Err(Error::ConcurrentWrite("the run's gated repo selection changed").into());
        }
        self.repo_lane_reads(binding, &[selected_repo])?;
        let membership = &admitted.membership;
        let queue = resolve_repo_queue_target(
            self.vault,
            selected_repo,
            &membership.repo_ref,
            &input.git_ref,
        )?
        .map_err(refusal_error)?;
        let green = GitOid::parse_hex(queue.green.clone())?;
        let base = self
            .vault
            .capture_repo_snapshot_at_commit(queue.queue.repository(), &green)?;
        let selected: BTreeMap<String, Vec<u8>> = base
            .files
            .into_iter()
            .filter(|(path, _)| membership.bounds.admits_path(RepoAccessIntent::Read, path))
            .collect();
        // A run's work holds the masked copy of each admitted file a repo
        // mark covers (FIX 7608); its stamp keeps the canonical green.
        let copy = materialize_masked_repo(self.vault, selected, &RepoSecretAudience::Masked)?;
        // Each masked file's descriptor rides the work's receipt (FIX 8965).
        let projections = copy.projections();
        let selected = copy.into_contents();
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
            selected_repo.to_hex(),
            membership.repo_ref.clone(),
            Some(queue.green.clone()),
            entries,
        )?;
        let set = CodeViewSet::open(self.vault)?;
        let opened = set.materialize_tree_for_run(
            binding.actor.entity_ref(),
            snapshot.fork_hash,
            &selected,
            projections,
            |txn, view| {
                let (selected_again, hit_again, admission) =
                    self.vault.admit_repo_run_with_portable_in_txn(
                        txn,
                        binding,
                        input.repo,
                        input.portable_repo.as_ref(),
                        &input.git_ref,
                        selected.keys(),
                        RepoAccessIntent::Read,
                    )?;
                if selected_again != selected_repo || hit_again != portable_hit {
                    return Err(Error::ConcurrentWrite(
                        "the run's repo work selection changed",
                    ));
                }
                Ok(match admission {
                    Ok(again) if again.same_lease(&admitted) => Ok(again.stamp(
                        binding,
                        &input.git_ref,
                        &queue.green,
                        base.fork_hash,
                        view,
                    )),
                    Ok(_) => Err(RepoAccessRefusal::StaleLease),
                    Err(refused) => Err(refused),
                })
            },
        )?;
        let receipt = opened.map_err(refusal_error)?;
        let stamp = receipt
            .run
            .clone()
            .ok_or(Error::InvariantViolation("a run's work lost its stamp"))?;
        Ok(RepoRunAnswer {
            rows: vec![selected_repo],
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
