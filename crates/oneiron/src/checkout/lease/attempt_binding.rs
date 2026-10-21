//! One attempt's custody of a checkout epoch (FIX 6867, G1 PR3b; ASK 2).
//!
//! A BYOA CLI attempt dispatched against a checkout reserves that lease's
//! current epoch for itself in the dispatch writer, so two live tries never
//! share one writable id and epoch, the same agent's included. The attempt
//! generation that starts executing on it is saved before the sandbox runs,
//! and the capture and every lease-route push compare the same binding.
//! A reclaim's new epoch carries no binding; a renewal keeps it. The binding
//! rides the existing lease row as one optional key, written only when an
//! attempt holds the epoch, so an unbound lease (every owner checkout) keeps
//! its bytes. No new table or record.

use rmpv::Value;

use super::codec::{load_act_in_txn, store_act_in_txn};
use super::types::{
    CheckoutError, CheckoutId, CheckoutLeaseAct, CheckoutLeaseState, CheckoutResult,
};
use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue};

/// The lease-row key the binding is stored under.
pub(super) const BOUND_ATTEMPT_KEY: &str = "bound_attempt";

/// The checkout is not live at this epoch for this holder.
pub(crate) const CHECKOUT_BINDING_STALE: &str =
    "the checkout lease is not live at this epoch for this holder";
/// Another attempt already holds this epoch.
pub(crate) const CHECKOUT_BINDING_SHARED: &str =
    "another attempt already holds this checkout epoch";
/// The binding names another attempt or epoch.
pub(crate) const CHECKOUT_BINDING_MISMATCH: &str = "the checkout epoch is bound to another attempt";

/// The attempt that holds one checkout epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckoutAttemptBinding {
    /// The attempt dispatched against the epoch.
    pub attempt: AttemptId,
    /// The epoch it holds: always the lease's current one.
    pub epoch: u64,
    /// The attempt generation that started executing on it, once one did.
    pub generation: Option<u32>,
}

/// The binding's lease-row value.
pub(super) fn encode_bound_attempt(binding: &CheckoutAttemptBinding) -> Value {
    Value::Map(vec![
        (
            Value::from("attempt"),
            Value::Binary(binding.attempt.as_bytes().to_vec()),
        ),
        (Value::from("epoch"), Value::from(binding.epoch)),
        (
            Value::from("generation"),
            binding.generation.map_or(Value::Nil, Value::from),
        ),
    ])
}

/// The binding a lease row at `epoch` stores, strictly: exactly its three
/// keys, at the row's own epoch.
pub(super) fn decode_bound_attempt(
    value: &Value,
    epoch: u64,
) -> CheckoutResult<CheckoutAttemptBinding> {
    let corrupt = || CheckoutError::Store(crate::Error::CorruptedIndex("checkout lease record"));
    let Value::Map(entries) = value else {
        return Err(corrupt());
    };
    if entries.len() != 3 {
        return Err(corrupt());
    }
    let field = |key: &str| {
        entries
            .iter()
            .find_map(|(k, v)| (k.as_str() == Some(key)).then_some(v))
            .ok_or_else(corrupt)
    };
    let attempt = field("attempt")?
        .as_slice()
        .filter(|bytes| bytes.len() == 16)
        .ok_or_else(corrupt)?;
    let binding = CheckoutAttemptBinding {
        attempt: AttemptId::from_bytes(attempt).map_err(CheckoutError::Store)?,
        epoch: field("epoch")?.as_u64().ok_or_else(corrupt)?,
        generation: match field("generation")? {
            Value::Nil => None,
            other => Some(
                other
                    .as_u64()
                    .and_then(|generation| u32::try_from(generation).ok())
                    .ok_or_else(corrupt)?,
            ),
        },
    };
    if binding.epoch != epoch {
        return Err(corrupt());
    }
    Ok(binding)
}

/// Whether `lease` is live at `epoch` for `holder` at the vault's own time
/// `now`: active, unexpired and not issued after it.
fn live_at(lease: &CheckoutLeaseAct, epoch: u64, holder: &str, now: u64) -> bool {
    lease.epoch == epoch
        && lease.holder_ref == holder
        && lease.state == CheckoutLeaseState::Active
        && lease.lease_expires_at.is_none_or(|expiry| now < expiry)
        && now >= lease.claimed_at
}

/// Reserves `checkout`'s epoch `epoch`, held by `holder`, for `attempt`,
/// in the dispatch writer `t`. The same attempt again is the same
/// reservation; another attempt is refused, never rebound. The inner
/// refusal is the stable reason; the outer error a store failure.
///
/// # Errors
/// A store failure.
pub(crate) fn reserve_attempt_in_txn(
    vault: &Vault,
    t: &mut heed::RwTxn<'_>,
    checkout: CheckoutId,
    epoch: u64,
    holder: &str,
    attempt: AttemptId,
) -> CheckoutResult<Result<CheckoutLeaseAct, &'static str>> {
    let now = vault.instant_in_write_txn(t)?.secs();
    let Some(mut lease) = load_act_in_txn(vault, t, checkout)? else {
        return Ok(Err(CHECKOUT_BINDING_STALE));
    };
    if !live_at(&lease, epoch, holder, now) {
        return Ok(Err(CHECKOUT_BINDING_STALE));
    }
    match lease.bound_attempt {
        Some(bound) if bound.attempt == attempt => return Ok(Ok(lease)),
        Some(_) => return Ok(Err(CHECKOUT_BINDING_SHARED)),
        None => {}
    }
    lease.bound_attempt = Some(CheckoutAttemptBinding {
        attempt,
        epoch,
        generation: None,
    });
    store_act_in_txn(vault, t, &lease)?;
    Ok(Ok(lease))
}

/// Saves `generation` as the one executing `attempt` on `checkout`'s epoch
/// `epoch`, in a short writer before the sandbox starts: the lease must
/// still be live for `holder` and bound to this attempt. A later generation
/// of the same attempt (its own lease re-acquired) takes it over; the
/// attempt queue's lease is what judges which generation acts.
///
/// # Errors
/// A store failure.
pub(crate) fn start_attempt_in_txn(
    vault: &Vault,
    t: &mut heed::RwTxn<'_>,
    checkout: CheckoutId,
    epoch: u64,
    holder: &str,
    attempt: AttemptId,
    generation: u32,
) -> CheckoutResult<Result<CheckoutLeaseAct, &'static str>> {
    let now = vault.instant_in_write_txn(t)?.secs();
    let Some(mut lease) = load_act_in_txn(vault, t, checkout)? else {
        return Ok(Err(CHECKOUT_BINDING_STALE));
    };
    if !live_at(&lease, epoch, holder, now) {
        return Ok(Err(CHECKOUT_BINDING_STALE));
    }
    let Some(bound) = lease.bound_attempt.filter(|bound| bound.attempt == attempt) else {
        return Ok(Err(CHECKOUT_BINDING_MISMATCH));
    };
    if bound.generation != Some(generation) {
        lease.bound_attempt = Some(CheckoutAttemptBinding {
            generation: Some(generation),
            ..bound
        });
        store_act_in_txn(vault, t, &lease)?;
    }
    Ok(Ok(lease))
}

/// Whether `checkout` still stands for `attempt` at its generation
/// `generation`, as read in `txn` at the vault's time: live at `epoch` for
/// `holder` and bound to exactly that attempt and generation.
///
/// # Errors
/// A store failure.
pub(crate) fn attempt_holds_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    checkout: CheckoutId,
    epoch: u64,
    holder: &str,
    attempt: AttemptId,
    generation: u32,
) -> CheckoutResult<bool> {
    let now = vault.instant_in_txn(txn)?.secs();
    Ok(load_act_in_txn(vault, txn, checkout)?.is_some_and(|lease| {
        live_at(&lease, epoch, holder, now)
            && lease.bound_attempt
                == Some(CheckoutAttemptBinding {
                    attempt,
                    epoch,
                    generation: Some(generation),
                })
    }))
}

/// The attempt-generation fence of a lease-route push (FIX 7130): an
/// unbound lease stands as before; a bound one stands only while its
/// attempt is still running at the generation that started on it.
///
/// # Errors
/// A store failure.
pub(crate) fn bound_attempt_runs_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    lease: &CheckoutLeaseAct,
) -> crate::Result<bool> {
    let Some(bound) = lease.bound_attempt else {
        return Ok(true);
    };
    let Some(generation) = bound.generation else {
        return Ok(false);
    };
    Ok(AttemptQueue::new(vault)
        .get_in_txn(txn, bound.attempt)?
        .is_some_and(|record| record.state.is_running() && record.attempt_count == generation))
}
