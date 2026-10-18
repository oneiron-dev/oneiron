//! Shared lease transitions. Door authorization and synced TASK facts run in the caller's
//! transaction around these same transitions; the trusted service uses them too.
use super::codec::{LEASE, SETTLEMENT, SettlementKey, load_act_in_txn,
    load_tombstone_in_txn, store_act_in_txn};
use super::types::*;
use super::checkout_result_identity;
use crate::Vault;

pub(crate) fn claim_in_txn(vault: &Vault, t: &mut heed::RwTxn<'_>, r: CheckoutClaimRequest) -> CheckoutResult<CheckoutLeaseAct> {
    CheckoutId::from_bytes(*r.checkout_id.as_bytes())?;
    if r.holder_ref.is_empty() {
        return Err(CheckoutError::Invalid("checkout holder empty"));
    }
    if load_act_in_txn(vault, t, r.checkout_id)?.is_some() {
        return Err(CheckoutError::StaleEpoch {
            held: 1,
            presented: 0,
        });
    }
    // Epochs are monotone per checkout_id *across* lifecycles: a fresh id
    // has no tombstone and starts at 1, while a re-claimed id resumes
    // above every epoch its earlier lifecycles ever held, so an old fence
    // can never match a new lifecycle.
    let epoch = load_tombstone_in_txn(vault, t, r.checkout_id)?
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(CheckoutError::Invalid("lease epoch overflow"))?;
    let expires = r
        .ttl_secs
        .map(|ttl| {
            r.now
                .checked_add(ttl)
                .ok_or(CheckoutError::Invalid("lease expiry overflow"))
        })
        .transpose()?;
    // On the clock `checkout_act` redeems against, not the
    // caller's `now`: a wall second can run ahead of the vault's
    // authority clock, and the fresh lease then read as unissued.
    let claimed_at = vault.instant_in_write_txn(t)?.secs();
    let a = CheckoutLeaseAct {
        checkout_id: r.checkout_id,
        task_ref: r.task_ref,
        repo_ref: r.repo_ref.clone(),
        holder_ref: r.holder_ref.clone(),
        epoch,
        task_class: r.task_class,
        state: CheckoutLeaseState::Active,
        claimed_at,
        lease_expires_at: expires,
        updated_at: r.now,
    };
    store_act_in_txn(vault, t, &a)?;
    Ok(a)
}

pub(crate) fn renew_in_txn(vault: &Vault, t: &mut heed::RwTxn<'_>, f: &CheckoutLeaseFence, ttl: u64, now: u64) -> CheckoutResult<CheckoutLeaseAct> {
    let mut a = fenced_in_txn(vault, t, f)?;
    require_not_regressed(&a, now)?;
    require_live(&a, now)?;
    a.lease_expires_at = Some(
        now.checked_add(ttl)
            .ok_or(CheckoutError::Invalid("lease expiry overflow"))?,
    );
    a.updated_at = now;
    store_act_in_txn(vault, t, &a)?;
    Ok(a)
}

pub(crate) fn reclaim_in_txn(vault: &Vault, t: &mut heed::RwTxn<'_>, id: CheckoutId, new: String, now: u64, expected_epoch: Option<u64>, manual: bool) -> CheckoutResult<(CheckoutLeaseAct, bool)> {
    if new.is_empty() {
        return Err(CheckoutError::Invalid("checkout holder empty"));
    }
    let mut a = load_act_in_txn(vault, t, id)?
        .ok_or(CheckoutError::Invalid("checkout missing"))?;
    require_not_regressed(&a, now)?;
    require_active(&a)?;
    if a.holder_ref == new && expected_epoch.is_none() {
        return Ok((a, false));
    }
    if let Some(expected) = expected_epoch
        && a.epoch != expected
    {
        return Err(CheckoutError::StaleEpoch { held: a.epoch, presented: expected });
    }
    let expiry = a
        .lease_expires_at
        .ok_or(CheckoutError::Invalid("ttl reclaim requires ttl"))?;
    if !manual && (!a.task_class.allows_ttl_reclaim() || now < expiry) {
        return Err(CheckoutError::StaleEpoch {
            held: a.epoch,
            presented: a.epoch,
        });
    }
    let ttl = expiry
        .checked_sub(a.updated_at)
        .ok_or(CheckoutError::Invalid("invalid lease ttl"))?;
    a.epoch = a
        .epoch
        .checked_add(1)
        .ok_or(CheckoutError::Invalid("lease epoch overflow"))?;
    a.holder_ref = new.clone();
    a.claimed_at = vault.instant_in_write_txn(t)?.secs();
    a.updated_at = now;
    a.lease_expires_at = Some(
        now.checked_add(ttl)
            .ok_or(CheckoutError::Invalid("lease expiry overflow"))?,
    );
    store_act_in_txn(vault, t, &a)?;
    Ok((a, true))
}

pub(crate) fn settle_in_txn(vault: &Vault, t: &mut heed::RwTxn<'_>, r: &CheckoutSettlementRequest) -> CheckoutResult<(CheckoutLeaseAct, CheckoutSettlementReceipt, bool)> {
    let mut a = fenced_in_txn(vault, t, &r.fence)?;
    require_not_regressed(&a, r.now)?;
    let identity = checkout_result_identity(
        a.checkout_id,
        a.epoch,
        &r.observed_ref,
        &r.result_ref,
    );
    let key = SettlementKey {
        checkout_id: a.checkout_id,
        epoch: a.epoch,
    };
    if let Some(old) = SETTLEMENT.get(&vault.store, &*t, &key)? {
        if old.checkout_id == a.checkout_id
            && old.epoch == a.epoch
            && old.result_identity == identity
            && old.disposition == r.disposition
            && old.observed_ref == r.observed_ref
            && old.result_ref == r.result_ref
        {
            return Ok((a, old, false));
        }
        return Err(CheckoutError::SettlementAlreadyWon);
    }
    if a.state == CheckoutLeaseState::Settled {
        return Err(CheckoutError::SettlementAlreadyWon);
    }
    require_unexpired(&a, r.now)?;
    require_settleable(&a)?;
    let receipt = CheckoutSettlementReceipt {
        receipt_id: *blake3::hash(
            &[identity.as_slice(), &r.now.to_le_bytes()].concat(),
        )
        .as_bytes(),
        checkout_id: a.checkout_id,
        epoch: a.epoch,
        result_identity: identity,
        disposition: r.disposition,
        observed_ref: r.observed_ref.clone(),
        result_ref: r.result_ref.clone(),
        settled_at: r.now,
    };
    SETTLEMENT.put(&vault.store, t, &key, &receipt)?;
    a.state = CheckoutLeaseState::Settled;
    a.updated_at = r.now;
    store_act_in_txn(vault, t, &a)?;
    Ok((a, receipt, true))
}

pub(crate) fn require_not_regressed(a: &CheckoutLeaseAct, now: u64) -> CheckoutResult<()> {
    if now < a.updated_at {
        Err(CheckoutError::Invalid("checkout time regressed"))
    } else {
        Ok(())
    }
}
fn require_settleable(a: &CheckoutLeaseAct) -> CheckoutResult<()> {
    if matches!(
        a.state,
        CheckoutLeaseState::Active | CheckoutLeaseState::Settled | CheckoutLeaseState::Retained
    ) {
        Ok(())
    } else {
        Err(CheckoutError::StaleEpoch {
            held: a.epoch,
            presented: a.epoch,
        })
    }
}
pub(crate) fn require_settling(a: &CheckoutLeaseAct) -> CheckoutResult<()> {
    if a.state == CheckoutLeaseState::Settling {
        Ok(())
    } else {
        Err(CheckoutError::StaleEpoch {
            held: a.epoch,
            presented: a.epoch,
        })
    }
}
pub(crate) fn require_active(a: &CheckoutLeaseAct) -> CheckoutResult<()> {
    if a.state == CheckoutLeaseState::Active {
        Ok(())
    } else {
        Err(CheckoutError::StaleEpoch {
            held: a.epoch,
            presented: a.epoch,
        })
    }
}
pub(crate) fn fenced_in_txn(
    vault: &Vault,
    t: &mut heed::RwTxn<'_>,
    f: &CheckoutLeaseFence,
) -> CheckoutResult<CheckoutLeaseAct> {
    let a = load_act_in_txn(vault, t, f.checkout_id)?
        .ok_or(CheckoutError::Invalid("checkout missing"))?;
    if a.epoch != f.epoch || a.holder_ref != f.holder_ref {
        Err(CheckoutError::StaleEpoch {
            held: a.epoch,
            presented: f.epoch,
        })
    } else {
        Ok(a)
    }
}
pub(crate) fn require_unexpired(a: &CheckoutLeaseAct, now: u64) -> CheckoutResult<()> {
    if now < a.claimed_at || a.lease_expires_at.is_some_and(|expiry| now >= expiry) {
        return Err(CheckoutError::StaleEpoch { held: a.epoch, presented: a.epoch });
    }
    Ok(())
}
pub(crate) fn require_live(a: &CheckoutLeaseAct, now: u64) -> CheckoutResult<()> {
    require_not_regressed(a, now)?;
    require_active(a)?;
    require_unexpired(a, now)
}

/// A published candidate's deterministic identity, fenced at publication time.
pub(crate) fn publish_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    fence: &CheckoutLeaseFence,
    observed: &str,
    candidate: &str,
    now: u64,
) -> CheckoutResult<[u8; 32]> {
    let act = fenced_in_txn(vault, txn, fence)?;
    require_live(&act, now)?;
    if observed.is_empty() || candidate.is_empty() {
        return Err(CheckoutError::Invalid("publication references empty"));
    }
    Ok(checkout_result_identity(act.checkout_id, act.epoch, observed, candidate))
}

pub(crate) fn finish_teardown_in_txn(
    vault: &Vault, txn: &mut heed::RwTxn<'_>, fence: &CheckoutLeaseFence, now: u64,
) -> CheckoutResult<CheckoutLeaseAct> {
    use super::codec::{TOMBSTONE, TombstoneRow};
    let act = fenced_in_txn(vault, txn, fence)?;
    require_not_regressed(&act, now)?;
    require_settling(&act)?;
    let prior = load_tombstone_in_txn(vault, txn, act.checkout_id)?.unwrap_or(0);
    TOMBSTONE.put(&vault.store, txn, &act.checkout_id, &TombstoneRow(prior.max(act.epoch)))?;
    LEASE.delete(&vault.store, txn, &act.checkout_id)?;
    Ok(act)
}
