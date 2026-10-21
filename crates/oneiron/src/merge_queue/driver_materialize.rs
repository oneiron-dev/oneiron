//! The driver's custody of staged objects and saved paths, and its overlap
//! preflight (FIX 6868, G2 PR2).
//!
//! The driver's staging runs the one staging body and pins every candidate
//! commit before the batch is saved Staged; worktree registration alone is
//! not custody. A saved path is put back at exactly its saved commit through
//! the journaled GitWire worktree, never rebuilt as a new commit: a check's
//! inputs name that commit. An occupied path, dirty bytes or a missing
//! object hold; nothing is deleted to make room. The overlap preflight
//! proves a same-base whole-file overlap from stored sources alone (CALL A).
use std::collections::BTreeSet;

use super::check_store::QueueCheckConfiguration;
use super::{
    BatchState, CheckPhase, MergeBatch, MergeProposal, MergeQueue, QueueBatchDrive, QueueDriveHold,
    QueueDriveHoldReason, QueueDriverTarget, QueueStageOverlap,
};
use crate::EntityId;
use crate::codebase::RepoRef;
use crate::contract_oracle::invalid;
use crate::error::{CodeError, Error, Result};
use crate::git_wire::{
    GitOid, GitWire, lock_repository, redact_bridged_failure, run_bridged_git_argv,
};
use crate::repo_mutation::proposal::RepoProposalOperation;

/// What the overlap preflight found for one batch.
pub(super) enum QueueOverlapFinding {
    /// No accepted proposal shares a write path with this batch's.
    None,
    /// A proven same-base overlap: hand it to a reconciliation.
    Overlap(Box<QueueStageOverlap>),
    /// An overlap the stored sources cannot prove: held, never guessed.
    Hold(QueueDriveHold),
}

impl MergeQueue<'_> {
    /// The branch HEAD is attached to, as the conflict target of a checked
    /// queue; `None` for a detached HEAD.
    pub(super) fn attached_target(&self, subject: EntityId) -> Result<Option<QueueDriverTarget>> {
        let args = ["symbolic-ref", "-q", "HEAD"].map(str::to_owned);
        let output = run_bridged_git_argv(self.repo.repo_root(), &args)?;
        if output.timed_out || output.truncated {
            return Err(Error::Code(CodeError::RepoMutationFailed(
                redact_bridged_failure(&args, output.exit_code, &output.stderr),
            )));
        }
        if !output.success {
            return Ok(None);
        }
        let full_ref = std::str::from_utf8(&output.stdout)
            .map_err(|_| invalid("git ref is not UTF-8"))?
            .trim()
            .to_owned();
        let Some(branch) = full_ref.strip_prefix("refs/heads/") else {
            return Ok(None);
        };
        Ok(Some(QueueDriverTarget {
            branch: branch.to_owned(),
            full_ref,
            branch_subject: subject,
        }))
    }

    /// The driver's staging: the one staging body, with every candidate
    /// commit pinned before the batch is saved Staged.
    pub(super) fn stage_driven(&self, id: &str) -> Result<MergeBatch> {
        let wire = GitWire::new(self.vault)?;
        self.stage_with(id, &mut |batch| self.pin_batch(&wire, batch))
    }

    /// Pins `batch`'s base, staged and landed commits with protected
    /// keep-refs and marks its drive record pinned. No pin is released here.
    pub(super) fn pin_batch(&self, wire: &GitWire<'_>, batch: &mut MergeBatch) -> Result<()> {
        let mut objects = vec![batch.expected_head.clone()];
        objects.extend(batch.paths.iter().map(|path| path.commit.clone()));
        objects.extend(batch.landed_head.clone());
        for object in objects {
            let _pinned = wire.write_keep_ref(&self.repo, &GitOid::parse_hex(object)?, 0)?;
        }
        let drive = batch.drive.get_or_insert_with(QueueBatchDrive::default);
        drive.pinned = true;
        drive.hold = None;
        Ok(())
    }

    /// Puts the saved path `mask` of `phase` back: a fast path at its saved
    /// commit, verified against its saved tree, commit and cleanliness; a
    /// slow path's stale registration is pruned so the checker re-adds it at
    /// the landed commit. `Ok(true)` when it changed the filesystem.
    pub(super) fn rematerialize(
        &self,
        batch: &MergeBatch,
        mask: u64,
        phase: CheckPhase,
    ) -> Result<std::result::Result<bool, QueueDriveHold>> {
        let _guard = lock_repository(self.repo.common_dir())?;
        let wire = GitWire::new(self.vault)?;
        let _recovered = wire.recover(&self.repo, 0)?;
        if phase == CheckPhase::Slow {
            let worktree = self.worktree_path(&batch.id, u64::MAX);
            if wire.worktree_registered(&self.repo, &worktree)?
                && worktree.symlink_metadata().is_err()
            {
                wire.prune_worktrees(&self.repo)?;
                return Ok(Ok(true));
            }
            return Ok(Ok(false));
        }
        let path = batch
            .paths
            .iter()
            .find(|path| path.mask == mask)
            .ok_or_else(|| invalid("speculative path not staged"))?;
        let held = |detail: String| {
            Ok(Err(QueueDriveHold::new(
                QueueDriveHoldReason::HeldMaterialization,
                detail,
            )))
        };
        let mut restored = false;
        let present = path.worktree.symlink_metadata().is_ok();
        if !present || !wire.worktree_registered(&self.repo, &path.worktree)? {
            if present {
                return held("the saved path is occupied outside its registration".to_owned());
            }
            if wire.worktree_registered(&self.repo, &path.worktree)? {
                wire.prune_worktrees(&self.repo)?;
            }
            let commit = GitOid::parse_hex(path.commit.clone())?;
            if let Err(error) = wire.add_worktree(&self.repo, &path.worktree, &commit, 0) {
                return held(format!(
                    "the saved commit cannot be checked out again: {error}"
                ));
            }
            restored = true;
        }
        if let Err(error) = self.verify_worktree(path) {
            return held(format!("the saved path is not as staged: {error}"));
        }
        Ok(Ok(restored))
    }
}

impl QueueStageOverlap {
    /// CALL A "whole-file queue overlap": two distinct accepted proposals
    /// that replace the same path from the same green base and retained
    /// snapshot, inside `batch` or against another retained batch, need a
    /// fresh combined reviewed proposal even when a text merge could be
    /// clean; equal target bytes count too, so no authorship is dropped. A
    /// shared symbol alone is not an overlap. A pair whose base or snapshot
    /// differs, or whose source is no stored proposal, holds. The first pair
    /// in batch and key order is the one handed off.
    pub(super) fn from_sources(
        queue: &MergeQueue<'_>,
        config: &QueueCheckConfiguration,
        batch: &MergeBatch,
        retained: &[MergeBatch],
    ) -> Result<QueueOverlapFinding> {
        // A source already handed off and superseded, or one whose handoff
        // this batch's own TASK resolves, is no new overlap.
        let resolved = |other: &MergeBatch| {
            other
                .drive
                .as_ref()
                .and_then(|drive| drive.overlap.as_ref())
                .is_some_and(|link| {
                    link.superseded
                        || batch
                            .run_order
                            .as_ref()
                            .is_some_and(|order| link.task == Some(order.task))
                })
        };
        let peers = retained.iter().filter(|other| {
            other.id != batch.id
                && other.base_green == batch.base_green
                && !resolved(other)
                && matches!(
                    other.state,
                    BatchState::Queued
                        | BatchState::Staged
                        | BatchState::Ready
                        | BatchState::Landing
                        | BatchState::HeadAdvanced
                        | BatchState::GreenAdvanced
                )
        });
        let mut found = None;
        'search: for (index, ours) in batch.proposals.iter().enumerate() {
            for theirs in &batch.proposals[index + 1..] {
                if !shared_paths(ours, theirs).is_empty() {
                    found = Some((ours, batch, theirs));
                    break 'search;
                }
            }
            for other in peers.clone() {
                for theirs in &other.proposals {
                    if theirs.id != ours.id && !shared_paths(ours, theirs).is_empty() {
                        found = Some((ours, other, theirs));
                        break 'search;
                    }
                }
            }
        }
        let Some((ours, other, theirs)) = found else {
            return Ok(QueueOverlapFinding::None);
        };
        let hold = |reason, detail: &str| {
            Ok(QueueOverlapFinding::Hold(QueueDriveHold::new(
                reason, detail,
            )))
        };
        let Some(target) = config.driver_target.clone() else {
            return hold(
                QueueDriveHoldReason::HeldOverlap,
                "overlapping proposals wait: the queue has no proven target branch",
            );
        };
        let paths = shared_paths(ours, theirs);
        if paths
            .iter()
            .any(|path| expected(ours, path) != expected(theirs, path))
        {
            return hold(
                QueueDriveHoldReason::HeldNeedsNewBase,
                "overlapping proposals were made on different bytes: a fresh reviewed proposal \
                 on the current base is needed",
            );
        }
        let mut rows = Vec::new();
        for proposal in [ours, theirs] {
            let row = match EntityId::from_hex(&proposal.id) {
                Ok(id) => queue.vault.repo_proposal(id)?,
                Err(_) => None,
            };
            let Some(row) = row else {
                return hold(
                    QueueDriveHoldReason::HeldOverlap,
                    "an overlapping proposal is no stored proposal; no conflict is guessed",
                );
            };
            let same_store = match RepoRef::parse(&row.repo) {
                Ok(RepoRef::LocalFolder { path, .. }) => GitWire::new(queue.vault)?
                    .repository_identity(std::path::Path::new(&path))
                    .is_ok_and(|store| store.as_hex() == queue.repo.identity().as_hex()),
                _ => false,
            };
            if !same_store || !matches!(row.operation, RepoProposalOperation::CommitFile) {
                return hold(
                    QueueDriveHoldReason::HeldOverlap,
                    "an overlapping proposal is not a whole-file proposal of this repository",
                );
            }
            rows.push(row);
        }
        if rows[0].pre_action_fork_hash != rows[1].pre_action_fork_hash {
            return hold(
                QueueDriveHoldReason::HeldNeedsNewBase,
                "overlapping proposals were made on different retained snapshots: a fresh \
                 reviewed proposal on the current base is needed",
            );
        }
        let mut sources = vec![rows[0].id, rows[1].id];
        sources.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        let batches: BTreeSet<String> = [batch.id.clone(), other.id.clone()].into();
        Ok(QueueOverlapFinding::Overlap(Box::new(Self {
            repo: config.repo,
            batches: batches.into_iter().collect(),
            target,
            base_green: batch.base_green.clone(),
            snapshot: rows[0].pre_action_fork_hash,
            sources,
            driven_source: rows[0].id,
            paths,
        })))
    }
}

/// The paths both proposals write, sorted.
fn shared_paths(ours: &MergeProposal, theirs: &MergeProposal) -> Vec<String> {
    let mine: BTreeSet<&str> = ours.files.iter().map(|file| file.path.as_str()).collect();
    let shared: BTreeSet<&str> = theirs
        .files
        .iter()
        .map(|file| file.path.as_str())
        .filter(|path| mine.contains(path))
        .collect();
    shared.into_iter().map(str::to_owned).collect()
}

/// The base bytes `proposal` expected at `path`.
fn expected<'p>(proposal: &'p MergeProposal, path: &str) -> Option<&'p Option<Vec<u8>>> {
    proposal
        .files
        .iter()
        .find(|file| file.path == path)
        .map(|file| &file.expected)
}
