//! Sending one frozen automatic mirror push plan (FIX 6866 part 2; CALLS "FIX
//! 6866 automatic retry").
//!
//! Batches go out in plan order, each under a claim written before its
//! child runs: one write transaction finds the plan still open on its
//! mirror, the batch unclaimed and the fence standing (the mirror row's URL,
//! user, custody record and generation are the plan's, its strategy and
//! revision are the plan's and still send whole refs, and this host is
//! still the origin), and marks the batch claimed. A fence that fell pauses
//! that batch and every later one: they are never sent. That is how a
//! switch to ask_me pauses unsent automatic work; a child already running is
//! never killed, and settles first. The child inherits the per-mirror hold,
//! so a batch a crash left claimed is read before anything is sent again. A
//! batch whose refs did not all land stops the plan there until its
//! reconcile settles them.

use std::collections::BTreeSet;

use super::mirror_plan::MirrorRunScope;
use super::mirror_plan_remote::bounded;
use super::mirror_plan_types::{
    MirrorBatchClaim, MirrorBatchProgress, MirrorPushPlan, MirrorRefOutcome,
};
use crate::Vault;
use crate::error::Result;
use crate::git_wire::{GitPlanPushReport, GitPlanRefOutcome};
use crate::origin::mirror::TARGETS;

impl Vault {
    /// Whether the plan may still send: its mirror row is the one it froze
    /// under, its strategy still sends whole refs, and this host is still
    /// the repository's origin.
    pub(super) fn mirror_fence_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        plan: &MirrorPushPlan,
    ) -> Result<bool> {
        let Some(target) = TARGETS.get(&self.store, txn, &plan.repo_id)? else {
            return Ok(false);
        };
        let destination = &plan.destination;
        Ok(target.url == destination.url
            && target.user == destination.user
            && target.secret_ref == destination.secret_ref
            && target.target_generation == destination.target_generation
            && target.sync_strategy == plan.strategy
            && target.strategy_revision == plan.strategy_revision
            && plan.strategy.pushes_whole_refs()
            && self.origin_pusher_stands_in_txn(txn, plan.repo_id)?)
    }

    /// Every ref a crashed run left claimed, now unknown: the caller holds
    /// the mirror, so no child of that run is alive.
    pub(super) fn release_stale_mirror_claims(&self, plan: &MirrorPushPlan) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        let batches = self.mirror_batches_in_txn(&txn, plan)?;
        let at = self.now_recorded_at();
        for (index, mut progress) in (0_u32..).zip(batches) {
            let mut changed = false;
            if matches!(progress.claim, MirrorBatchClaim::Claimed { .. }) {
                progress.claim = MirrorBatchClaim::Sent { at };
                changed = true;
            }
            for outcome in &mut progress.outcomes {
                if *outcome == MirrorRefOutcome::Dispatched {
                    *outcome = MirrorRefOutcome::Unknown;
                    changed = true;
                }
            }
            if changed {
                self.put_mirror_batch_in_txn(&mut txn, plan, index, &progress)?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    /// Sends the plan's next batches in order, each under its claim, until
    /// one does not land whole, the fence falls, or none is left.
    pub(super) fn send_mirror_plan(
        &self,
        scope: &MirrorRunScope<'_, '_>,
        plan: &MirrorPushPlan,
    ) -> Result<()> {
        for batch in 0..plan.batches {
            let progress = {
                let txn = self.store.env.read_txn()?;
                self.mirror_batch_in_txn(&txn, plan, batch)?
            };
            match progress.claim {
                MirrorBatchClaim::Paused => continue,
                MirrorBatchClaim::Sent { .. }
                    if progress.outcomes.iter().all(|outcome| outcome.settled()) =>
                {
                    continue;
                }
                MirrorBatchClaim::Pending => {}
                MirrorBatchClaim::Sent { .. } | MirrorBatchClaim::Claimed { .. } => return Ok(()),
            }
            let Some(members) = self.claim_mirror_batch(plan, batch)? else {
                return Ok(());
            };
            let report = self.push_mirror_plan_refs(scope, plan, &members);
            if !self.record_mirror_push(plan, &members, report, false)? {
                return Ok(());
            }
        }
        Ok(())
    }

    /// Claims one batch, fenced: its members, or `None` when it is not this
    /// call's to send. A fallen fence pauses it and every later batch.
    fn claim_mirror_batch(&self, plan: &MirrorPushPlan, batch: u32) -> Result<Option<Vec<u32>>> {
        let mut txn = self.store.env.write_txn()?;
        let head = self.mirror_work_head_in_txn(&txn, plan.repo_id)?;
        let batches = self.mirror_batches_in_txn(&txn, plan)?;
        let pending = batches
            .get(batch as usize)
            .is_some_and(|progress| progress.claim == MirrorBatchClaim::Pending);
        if head.open != Some(plan.plan_id) || !pending {
            return Ok(None);
        }
        let fenced = self.mirror_fence_in_txn(&txn, plan)?;
        let mut members = None;
        for (index, mut progress) in (0_u32..).zip(batches).skip(batch as usize) {
            if progress.claim != MirrorBatchClaim::Pending {
                continue;
            }
            let (claim, outcome) = if fenced && index == batch {
                members = Some(progress.refs.clone());
                let at = self.now_recorded_at();
                (
                    MirrorBatchClaim::Claimed { at },
                    MirrorRefOutcome::Dispatched,
                )
            } else if fenced {
                break;
            } else {
                (MirrorBatchClaim::Paused, MirrorRefOutcome::Paused)
            };
            progress.claim = claim;
            for slot in &mut progress.outcomes {
                if *slot == MirrorRefOutcome::Pending {
                    *slot = outcome;
                }
            }
            self.put_mirror_batch_in_txn(&mut txn, plan, index, &progress)?;
        }
        txn.commit()?;
        Ok(members)
    }

    /// Claims a same-plan resend of `members`, fenced. A fallen fence pauses
    /// `members` and the `rest` that would follow them instead: `false`.
    pub(super) fn claim_mirror_resend(
        &self,
        plan: &MirrorPushPlan,
        members: &[u32],
        rest: &[u32],
    ) -> Result<bool> {
        let mut txn = self.store.env.write_txn()?;
        let head = self.mirror_work_head_in_txn(&txn, plan.repo_id)?;
        if head.open != Some(plan.plan_id) {
            return Ok(false);
        }
        let fenced = self.mirror_fence_in_txn(&txn, plan)?;
        let changes: Vec<(u32, MirrorRefOutcome)> = if fenced {
            members
                .iter()
                .map(|index| (*index, MirrorRefOutcome::Dispatched))
                .collect()
        } else {
            members
                .iter()
                .chain(rest)
                .map(|index| (*index, MirrorRefOutcome::Paused))
                .collect()
        };
        self.write_mirror_outcomes_in_txn(&mut txn, plan, &changes, None, false)?;
        txn.commit()?;
        Ok(fenced)
    }

    /// Records what one child reported for `members`. A same-plan resend's
    /// refusal ends its ref. Whether every member landed.
    pub(super) fn record_mirror_push(
        &self,
        plan: &MirrorPushPlan,
        members: &[u32],
        report: Result<GitPlanPushReport>,
        resend: bool,
    ) -> Result<bool> {
        let (outcomes, detail) = match report {
            Ok(report) => (
                report
                    .outcomes
                    .iter()
                    .map(|outcome| match outcome {
                        GitPlanRefOutcome::Applied => MirrorRefOutcome::Applied,
                        GitPlanRefOutcome::Rejected if resend => MirrorRefOutcome::Refused,
                        GitPlanRefOutcome::Rejected => MirrorRefOutcome::Rejected,
                        GitPlanRefOutcome::Unknown => MirrorRefOutcome::Unknown,
                    })
                    .collect::<Vec<_>>(),
                report.failure,
            ),
            Err(error) => (
                vec![MirrorRefOutcome::Unknown; members.len()],
                Some(bounded(error.to_string())),
            ),
        };
        let landed =
            outcomes.len() == members.len() && outcomes.iter().all(|outcome| outcome.landed());
        let changes: Vec<(u32, MirrorRefOutcome)> = members.iter().copied().zip(outcomes).collect();
        let mut txn = self.store.env.write_txn()?;
        self.write_mirror_outcomes_in_txn(&mut txn, plan, &changes, detail, !resend)?;
        txn.commit()?;
        Ok(landed)
    }

    /// Writes ref outcomes into their batch rows; `sent` also marks each
    /// batch touched sent.
    pub(super) fn write_mirror_outcomes_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        plan: &MirrorPushPlan,
        changes: &[(u32, MirrorRefOutcome)],
        detail: Option<String>,
        sent: bool,
    ) -> Result<()> {
        let mut batches = self.mirror_batches_in_txn(txn, plan)?;
        let mut touched = BTreeSet::new();
        for (index, outcome) in changes {
            let Some(batch) = plan.refs.get(*index as usize).and_then(|r| r.batch) else {
                continue;
            };
            let Some(progress) = batches.get_mut(batch as usize) else {
                continue;
            };
            let Some(position) = progress.refs.iter().position(|member| member == index) else {
                continue;
            };
            if let Some(slot) = progress.outcomes.get_mut(position) {
                *slot = *outcome;
                touched.insert(batch);
            }
        }
        let at = self.now_recorded_at();
        for batch in touched {
            let Some(progress) = batches.get_mut(batch as usize) else {
                continue;
            };
            if sent {
                progress.claim = MirrorBatchClaim::Sent { at };
            }
            if detail.is_some() {
                progress.detail.clone_from(&detail);
            }
            self.put_mirror_batch_in_txn(txn, plan, batch, progress)?;
        }
        Ok(())
    }
}

/// Each ref's outcome, in plan order: a ref no batch holds needs no push (a
/// deletion the mirror already lacked, a covered full-auto ref).
pub(super) fn ref_outcomes(
    plan: &MirrorPushPlan,
    batches: &[MirrorBatchProgress],
) -> Vec<MirrorRefOutcome> {
    (0_u32..)
        .zip(&plan.refs)
        .map(|(index, plan_ref)| {
            let unbatched = if plan_ref.new.is_none() {
                MirrorRefOutcome::ObservedApplied
            } else {
                MirrorRefOutcome::Covered
            };
            plan_ref
                .batch
                .and_then(|batch| batches.get(batch as usize))
                .and_then(|progress| {
                    let position = progress.refs.iter().position(|member| *member == index)?;
                    progress.outcomes.get(position).copied()
                })
                .unwrap_or(unbatched)
        })
        .collect()
}
