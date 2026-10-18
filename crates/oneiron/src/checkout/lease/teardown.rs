//! Restartable teardown shared by the trusted service and credential doors.
use super::types::*;
use super::transactions::{fenced_in_txn, require_not_regressed};
use super::codec::store_act_in_txn;
use crate::Vault;

#[derive(Clone, Copy)]
pub(crate) enum TeardownStep { Prepare, Finish }

pub(crate) fn teardown_through<L: CheckoutLiveness, R: CheckoutRepoOps, E: From<CheckoutError>>(
    fence: &CheckoutLeaseFence,
    ops: &R,
    liveness: &mut L,
    mut write: impl FnMut(TeardownStep, &L) -> Result<(CheckoutLeaseAct, Option<CheckoutRetainReason>), E>,
) -> Result<CheckoutTeardownOutcome, E> {
    let (act, reason) = write(TeardownStep::Prepare, liveness)?;
    if let Some(reason) = reason {
        return Ok(CheckoutTeardownOutcome::Retained {
            checkout_id: act.checkout_id, epoch: act.epoch, reason,
        });
    }
    ops.collect(&act).map_err(E::from)?;
    let (retired, _) = write(TeardownStep::Finish, liveness)?;
    liveness.clear(fence.checkout_id, fence.epoch).map_err(E::from)?;
    Ok(CheckoutTeardownOutcome::Collected {
        checkout_id: retired.checkout_id, epoch: retired.epoch,
    })
}

/// Inspect custody and authorize collection in the same transaction. Git collection
/// remains outside LMDB, after the durable Settling intent, and is restartable.
pub(crate) fn prepare_teardown_in_txn<L: CheckoutLiveness, R: CheckoutRepoOps>(
    vault: &Vault, txn: &mut heed::RwTxn<'_>, fence: &CheckoutLeaseFence,
    receipt: Option<&PushedHeadReceipt>, ops: &R, liveness: &L, now: u64,
) -> CheckoutResult<(CheckoutLeaseAct, Option<CheckoutRetainReason>)> {
    let mut act = fenced_in_txn(vault, txn, fence)?;
    require_not_regressed(&act, now)?;
    if act.state == CheckoutLeaseState::Settling { return Ok((act, None)); }
    let reason = teardown_reason(&act, receipt, ops, liveness)?;
    act.state = if reason.is_some() { CheckoutLeaseState::Retained } else { CheckoutLeaseState::Settling };
    act.updated_at = now;
    store_act_in_txn(vault, txn, &act)?;
    Ok((act, reason))
}

fn teardown_reason<R: CheckoutRepoOps, L: CheckoutLiveness>(
    a: &CheckoutLeaseAct, receipt: Option<&PushedHeadReceipt>, ops: &R, liveness: &L,
) -> CheckoutResult<Option<CheckoutRetainReason>> {
    let Some(r) = receipt else {
        return Ok(Some(CheckoutRetainReason::MissingPushedHeadReceipt));
    };
    if r.checkout_id != a.checkout_id || r.epoch != a.epoch {
        return Ok(Some(CheckoutRetainReason::ReceiptMismatch));
    }
    let i = ops.inspect_teardown(a, r)?;
    let pulse = liveness.current(a.checkout_id)?;
    let head_matches = i.observed_head.as_ref().is_some_and(|h| h.to_string() == r.pushed_head);
    let foreign = i.occupant.as_deref().is_some_and(|holder| holder != a.holder_ref)
        || pulse.as_ref().is_some_and(|p| p.checkout_id != a.checkout_id
            || p.epoch != a.epoch || p.holder_ref != a.holder_ref);
    Ok(if foreign { Some(CheckoutRetainReason::LiveOccupant) }
        else if i.dirty || i.receipt_match == TeardownReceiptMatch::Uncertain {
            Some(CheckoutRetainReason::DirtyOrUncertain)
        } else if i.receipt_match != TeardownReceiptMatch::Match || !head_matches {
            Some(CheckoutRetainReason::ReceiptMismatch)
        } else { None })
}
