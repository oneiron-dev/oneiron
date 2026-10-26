//! Reconciling an automatic mirror push plan before any resend (FIX 6866 part
//! 2; CALLS "FIX 6866 automatic retry" and "FIX 6866 automatic unreadable
//! reconcile").
//!
//! A ref whose push did not prove its own outcome (no acknowledgement, a
//! first refusal, or a claim a crash left) is read again at the mirror with
//! the mirror's credential before anything is sent again. At its new object
//! (a deletion: absent), it settles and is never resent. At the tip the plan
//! leased on, it gets the same-plan resend only: the same ref, the same
//! object, the same lease. At neither, or when the plan read no tip to lease
//! on, it ends `remote_moved`. A resend the mirror refuses again ends
//! `refused`. Nothing is ever recomputed or widened: a new plan waits for
//! this one to settle.
//!
//! A ref the publication gate held (`secret_hold`) is read the same way
//! before its same-plan send asks the gate again; one the plan read no tip
//! for goes unleased, as it was planned.
//!
//! When the read itself fails, the plan stays frozen and the read is tried
//! again at the next opportunity; once it has failed
//! [`AUTOMATIC_RECONCILE_UNREAD_BEFORE_RESEND`] times in a row, each further
//! opportunity resends that same frozen tuple (exact refs and objects,
//! forced and with deletions, each under its frozen lease), never a broader
//! or newer plan (Engine E1, 10-21 09:5x).

use super::mirror_plan::MirrorRunScope;
use super::mirror_plan_dispatch::ref_outcomes;
use super::mirror_plan_types::{MirrorObservedTip, MirrorPushPlan, MirrorRefOutcome};
use crate::Vault;
use crate::error::Result;
use crate::git_wire::{GitRefName, MIRROR_PUSH_REFSPECS};

/// Whether an unproven automatic push whose reconcile read keeps failing
/// resends its same frozen tuple (Engine E1; CALLS "FIX 6866 automatic
/// unreadable reconcile").
pub const AUTOMATIC_UNREADABLE_RECONCILE_RESENDS_SAME_PLAN: bool = true;

/// Reconcile reads that fail in a row before the same frozen tuple goes out
/// again: the first failure waits for the next tick or wake, the second
/// resends (Engine E1).
pub const AUTOMATIC_RECONCILE_UNREAD_BEFORE_RESEND: u32 = 2;

/// How one reconcile went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MirrorReconcile {
    /// Nothing was unproven.
    Nothing,
    /// The read answered: each unproven ref settled or was resent.
    Read,
    /// The read failed, `unread` times in a row now, with its redacted
    /// cause; past the bound, the frozen tuple was resent.
    Unreadable { cause: String, unread: u32 },
}

impl Vault {
    /// Reads what the plan's unproven refs hold at the mirror and settles or
    /// resends each, as the module says.
    pub(super) fn reconcile_mirror_plan(
        &self,
        scope: &MirrorRunScope<'_, '_>,
        plan: &MirrorPushPlan,
    ) -> Result<MirrorReconcile> {
        let outcomes = {
            let txn = self.store.env.read_txn()?;
            ref_outcomes(plan, &self.mirror_batches_in_txn(&txn, plan)?)
        };
        let unproven: Vec<u32> = (0_u32..)
            .zip(&outcomes)
            .filter(|(_, outcome)| outcome.unproven())
            .map(|(index, _)| index)
            .collect();
        if unproven.is_empty() {
            return Ok(MirrorReconcile::Nothing);
        }
        let names = unproven
            .iter()
            .filter_map(|index| plan.refs.get(*index as usize))
            .map(|plan_ref| GitRefName::parse_full(plan_ref.ref_name.clone()))
            .collect::<Result<Vec<_>>>()?;
        let observed = self.observe_mirror_refs(scope, &plan.destination, &names);
        let failed = observed.values().find_map(|tip| match tip {
            MirrorObservedTip::Unknown { cause } => Some(cause.clone()),
            MirrorObservedTip::Absent | MirrorObservedTip::At { .. } => None,
        });
        if let Some(cause) = failed {
            let unread = self.count_mirror_unread(plan, true)?;
            if AUTOMATIC_UNREADABLE_RECONCILE_RESENDS_SAME_PLAN
                && unread >= AUTOMATIC_RECONCILE_UNREAD_BEFORE_RESEND
            {
                self.resend_mirror_refs(scope, plan, &unproven)?;
            }
            return Ok(MirrorReconcile::Unreadable { cause, unread });
        }
        self.count_mirror_unread(plan, false)?;
        let mut settled = Vec::new();
        let mut resend = Vec::new();
        for (index, name) in unproven.iter().zip(&names) {
            let Some(plan_ref) = plan.refs.get(*index as usize) else {
                continue;
            };
            let now = observed.get(name).and_then(MirrorObservedTip::oid);
            let at_new = now == plan_ref.new.as_deref();
            let at_old = match &plan_ref.observed {
                MirrorObservedTip::Absent => now.is_none(),
                MirrorObservedTip::At { oid } => now == Some(oid.as_str()),
                // A held ref was never sent: it goes unleased, as planned.
                MirrorObservedTip::Unknown { .. } => {
                    outcomes.get(*index as usize) == Some(&MirrorRefOutcome::Held)
                }
            };
            if at_new {
                settled.push((*index, MirrorRefOutcome::ObservedApplied));
            } else if at_old {
                resend.push(*index);
            } else {
                settled.push((*index, MirrorRefOutcome::RemoteMoved));
            }
        }
        let mut txn = self.store.env.write_txn()?;
        self.write_mirror_outcomes_in_txn(&mut txn, plan, &settled, None, false)?;
        txn.commit()?;
        self.resend_mirror_refs(scope, plan, &resend)?;
        Ok(MirrorReconcile::Read)
    }

    /// The same-plan resend of `members`, in plan order, each batch claimed
    /// and fenced; a fallen fence pauses what is left.
    fn resend_mirror_refs(
        &self,
        scope: &MirrorRunScope<'_, '_>,
        plan: &MirrorPushPlan,
        members: &[u32],
    ) -> Result<()> {
        let mut offset = 0;
        for chunk in members.chunks(MIRROR_PUSH_REFSPECS) {
            offset += chunk.len();
            let rest = members.get(offset..).unwrap_or_default();
            if !self.claim_mirror_resend(plan, chunk, rest)? {
                return Ok(());
            }
            let report = self.push_mirror_plan_refs(scope, plan, chunk);
            if !self.record_mirror_push(plan, chunk, report, true)? {
                return Ok(());
            }
        }
        Ok(())
    }

    /// Counts one more failed read in a row (`failed`), or clears the
    /// count; the count as it stands.
    fn count_mirror_unread(&self, plan: &MirrorPushPlan, failed: bool) -> Result<u32> {
        let mut txn = self.store.env.write_txn()?;
        let mut head = self.mirror_work_head_in_txn(&txn, plan.repo_id)?;
        if head.open != Some(plan.plan_id) {
            return Ok(0);
        }
        let unread = if failed {
            head.unread.saturating_add(1)
        } else {
            0
        };
        if unread != head.unread {
            head.unread = unread;
            self.put_mirror_work_head_in_txn(&mut txn, plan.repo_id, &head)?;
            txn.commit()?;
        }
        Ok(unread)
    }
}
