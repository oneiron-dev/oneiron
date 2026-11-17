//! Reconciliation links follow accepted conflict-path coverage and the green
//! carry-over of a handed-off batch's other files, not TASK completion.
//! Coverage that supersedes the sources also keeps what closed the conflict,
//! and that save completes the reconciliation TASK (`update_overlap_links`).
use std::collections::{BTreeMap, BTreeSet};

use super::{
    BatchState, CheckPhase, MergeBatch, MergeProposal, MergeQueue, QUEUE_CHECK_CANDIDATE_PREFIX,
    QueueCheckTarget, QueueConflictLink, QueueConflictResolver, SpeculativePath,
};
use crate::codebase::RepoRef;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::git_wire::{lock_repository, mutation_commands::repo_mutation_repo_key};
use crate::repo_mutation::RepoConflictClaim;
use crate::repo_mutation::proposal::{RepoProposalOperation, RepoProposalStatus};
use crate::store::contract_oracle::ContractOracle;

impl MergeQueue<'_> {
    pub(super) fn reconcile_conflict_resolution(
        &self,
        link: &mut QueueConflictLink,
        retained: &[MergeBatch],
    ) -> Result<bool> {
        // A successor counts only once the reconciliation TASK exists.
        if link.task.is_none() {
            return Ok(false);
        }
        let _guard = lock_repository(self.repo.common_dir())?;
        let Some(target) = self
            .initialized_configuration()?
            .ok()
            .and_then(|config| config.driver_target)
        else {
            return Ok(false);
        };
        let Some(open) = self
            .vault
            .repo_conflict_claim_history(&link.branch_subject)?
            .into_iter()
            .find(|open| open.claim_id == link.conflict)
        else {
            return Ok(false);
        };
        if target.branch_subject != open.subject
            || target.branch != open.branch
            || open.proposals != link.sources
            || repo_mutation_repo_key(&open.repo_ref)
                != repo_mutation_repo_key(self.repo.repo_ref())
        {
            return Ok(false);
        }
        let mut remaining: BTreeSet<_> = open.conflicted_paths.iter().cloned().collect();
        // A handed-off batch ends Superseded as a whole, so a file it writes
        // that no conflicted path names (a bundle source's unshared file, or
        // another proposal's file in the same batch) is lost unless some
        // green batch has since landed that path. Those paths wait below,
        // beside the conflicted ones, before any source is superseded.
        let unshared = unshared_batch_paths(link, retained, &remaining);
        let mut unshared_remaining: BTreeSet<_> = unshared.keys().cloned().collect();
        let mut successor = None;
        let mut last_green = None;
        let mut recorded = false;
        for retained in retained {
            let source_batch = link.batches.contains(&retained.id);
            if source_batch && unshared.is_empty() {
                continue;
            }
            // The successor is matched by the conflict its proposals resolve
            // (conflict_proposal_paths), not by the TASK it runs under: no
            // run is leased on the reconciliation TASK itself (RULING
            // CODECUSTODY-RECONCILE-SUCCESSOR = A).
            let batch = self.batch(&retained.id)?;
            if matches!(
                batch.state,
                BatchState::Cancelled
                    | BatchState::RolledBack
                    | BatchState::Quarantined
                    | BatchState::Superseded
            ) {
                continue;
            }
            if batch.state == BatchState::GreenAdvanced {
                let Some(path) = self.historical_green_path(&batch)? else {
                    continue;
                };
                let mut covered = BTreeSet::new();
                let mut carried = BTreeSet::new();
                for (index, proposal) in batch.proposals.iter().enumerate() {
                    if path.mask & (1_u64 << index) != 0 {
                        if !source_batch {
                            covered.extend(self.conflict_proposal_paths(
                                &open,
                                proposal,
                                Some(&batch.id),
                            )?);
                        }
                        if !unshared.is_empty() {
                            carried.extend(
                                self.applied_proposal_paths(&open, proposal, &batch, &unshared)?,
                            );
                        }
                    }
                }
                // A source batch that itself reached green already landed
                // its files; it still resolves no conflict of its own, so
                // its conflict coverage is neither computed nor recorded.
                for path in carried {
                    unshared_remaining.remove(&path);
                }
                if source_batch {
                    continue;
                }
                let (covered, changed) = self.vault.record_queue_repo_conflict_resolution(
                    self.repo.repo_ref(),
                    &open,
                    &batch.id,
                    &path.tree,
                    covered.into_iter().collect(),
                )?;
                recorded |= changed;
                if !covered.is_empty() {
                    for path in covered {
                        remaining.remove(&path);
                    }
                    last_green = Some((batch.id, batch.run_order));
                }
            } else if successor.is_none() && !source_batch {
                for proposal in &batch.proposals {
                    if !self
                        .conflict_proposal_paths(&open, proposal, None)?
                        .is_empty()
                    {
                        successor = Some(batch.id.clone());
                        break;
                    }
                }
            }
        }
        let superseded =
            remaining.is_empty() && unshared_remaining.is_empty() && last_green.is_some();
        // What closed it, kept with the supersession: the claim the
        // reconciliation TASK completes with, and the run whose green
        // entry made it (FIX QUEUE-RECONCILIATION-TASK-COMPLETION).
        let resolved_by = match &last_green {
            Some((batch, run)) if superseded => Some(QueueConflictResolver {
                resolution: self.vault.queue_conflict_closing_resolution(
                    self.repo.repo_ref(),
                    &open,
                    batch,
                )?,
                task: run.as_ref().map(|run| run.task),
                work: run.as_ref().map(|run| run.work),
            }),
            _ => None,
        };
        let last_green = last_green.map(|(batch, _)| batch);
        let resolution = if superseded {
            last_green
        } else {
            successor.or(last_green)
        };
        let changed = recorded
            || link.resolution_batch != resolution
            || link.superseded != superseded
            || link.resolved_by != resolved_by;
        link.resolution_batch = resolution;
        link.superseded = superseded;
        link.resolved_by = resolved_by;
        Ok(changed)
    }

    fn conflict_proposal_paths(
        &self,
        open: &RepoConflictClaim,
        candidate: &MergeProposal,
        applied_batch: Option<&str>,
    ) -> Result<Vec<String>> {
        let Some(row) = EntityId::from_hex(&candidate.id)
            .ok()
            .map(|id| self.vault.repo_proposal(id))
            .transpose()?
            .flatten()
        else {
            return Ok(Vec::new());
        };
        if repo_mutation_repo_key(&RepoRef::parse(&row.repo)?)
            != repo_mutation_repo_key(&open.repo_ref)
            || applied_batch.is_some_and(|batch| {
                row.status != RepoProposalStatus::Applied
                    || row.operation_seq.is_none()
                    || row.merge_stack.as_deref() != Some(batch)
            })
        {
            return Ok(Vec::new());
        }
        // Only a resolution of this open conflict counts: another change to a
        // conflicted path does not resolve it.
        let RepoProposalOperation::ResolveConflictFile {
            branch_subject,
            open_conflict_claim_id,
            branch_name,
        } = &row.operation
        else {
            return Ok(Vec::new());
        };
        if *branch_subject != open.subject
            || *open_conflict_claim_id != open.claim_id
            || branch_name != &open.branch
        {
            return Ok(Vec::new());
        }
        Ok(row
            .files
            .iter()
            .filter(|file| {
                open.conflicted_paths.contains(&file.path)
                    && candidate
                        .files
                        .iter()
                        .any(|queued| queued.path == file.path)
            })
            .map(|file| file.path.clone())
            .collect())
    }

    /// The `wanted` paths `candidate` landed as an applied proposal of
    /// `applied_batch`, by any operation: an unshared file is carried by a
    /// fresh proposal that lands it, not by a resolution, whose guard
    /// names only a conflicted path. It must follow every pending source
    /// that writes the path; the source's base green predates its acceptance.
    /// Missing acceptance order proves no carry-over. The applied checks are
    /// the ones [`Self::conflict_proposal_paths`] makes for a green batch.
    fn applied_proposal_paths(
        &self,
        open: &RepoConflictClaim,
        candidate: &MergeProposal,
        applied_batch: &MergeBatch,
        wanted: &BTreeMap<String, Option<u64>>,
    ) -> Result<Vec<String>> {
        let Some(order) = &applied_batch.run_order else {
            return Ok(Vec::new());
        };
        let Some(row) = EntityId::from_hex(&candidate.id)
            .ok()
            .map(|id| self.vault.repo_proposal(id))
            .transpose()?
            .flatten()
        else {
            return Ok(Vec::new());
        };
        if repo_mutation_repo_key(&RepoRef::parse(&row.repo)?)
            != repo_mutation_repo_key(&open.repo_ref)
            || row.status != RepoProposalStatus::Applied
            || row.operation_seq.is_none()
            || row.merge_stack.as_deref() != Some(applied_batch.id.as_str())
        {
            return Ok(Vec::new());
        }
        Ok(row
            .files
            .iter()
            .filter(|file| {
                wanted
                    .get(&file.path)
                    .copied()
                    .flatten()
                    .is_some_and(|sequence| order.sequence > sequence)
                    && candidate
                        .files
                        .iter()
                        .any(|queued| queued.path == file.path)
            })
            .map(|file| file.path.clone())
            .collect())
    }

    /// Read the slow check's original path, even after an erase changes the
    /// reviewed stack or a later green advances the live pointers.
    fn historical_green_path<'b>(
        &self,
        batch: &'b MergeBatch,
    ) -> Result<Option<&'b SpeculativePath>> {
        let (Some(commit), Some(verdict)) = (&batch.landed_head, &batch.slow_verdict) else {
            return Ok(None);
        };
        let Some(verdict) = ContractOracle::new(self.vault).verdict(verdict)? else {
            return Ok(None);
        };
        if !verdict.passes() || verdict.baseline_id != batch.baseline_id {
            return Ok(None);
        }
        if let Some(digest) = verdict.candidate.strip_prefix(QUEUE_CHECK_CANDIDATE_PREFIX) {
            let Some(receipt) = self.bound_receipt(digest, &verdict.id)? else {
                return Ok(None);
            };
            if receipt.inputs.store != self.repo.identity().as_hex()
                || receipt.inputs.baseline_id.as_deref() != Some(batch.baseline_id.as_str())
                || receipt.inputs.digest()? != digest
            {
                return Ok(None);
            }
            let QueueCheckTarget::Candidate {
                batch: id,
                mask,
                phase: CheckPhase::Slow,
                commit: checked_commit,
                tree,
            } = &receipt.inputs.target
            else {
                return Ok(None);
            };
            return Ok((id == &batch.id && checked_commit == commit)
                .then(|| {
                    batch
                        .paths
                        .iter()
                        .find(|path| path.mask == *mask && &path.tree == tree)
                })
                .flatten());
        }
        for path in &batch.paths {
            if self.require_check_binding(
                batch,
                path.mask,
                &path.tree,
                commit,
                CheckPhase::Slow,
                &verdict,
                None,
            )? {
                return Ok(Some(path));
            }
        }
        Ok(None)
    }
}

/// Every path an unlanded batch of `link` writes that `conflicted` does not
/// name, with the latest source acceptance sequence a carrying batch must
/// follow. An unknown source order keeps the path uncarried. A landed batch
/// keeps its state and its receipt when its link supersedes, so only the
/// states that end Superseded count, as in `update_overlap_links`.
fn unshared_batch_paths(
    link: &QueueConflictLink,
    retained: &[MergeBatch],
    conflicted: &BTreeSet<String>,
) -> BTreeMap<String, Option<u64>> {
    let mut unshared = BTreeMap::new();
    for batch in retained.iter().filter(|batch| {
        link.batches.contains(&batch.id)
            && matches!(
                batch.state,
                BatchState::Queued | BatchState::Staged | BatchState::Ready
            )
    }) {
        let sequence = batch.run_order.as_ref().map(|order| order.sequence);
        for file in batch.proposals.iter().flat_map(|proposal| &proposal.files) {
            if !conflicted.contains(&file.path) {
                unshared
                    .entry(file.path.clone())
                    .and_modify(|latest: &mut Option<u64>| {
                        *latest = (*latest).zip(sequence).map(|(a, b)| a.max(b));
                    })
                    .or_insert(sequence);
            }
        }
    }
    unshared
}
