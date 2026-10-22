//! A wait's replies in checkpoint images (FIX 6588, KEY STORE = A): each
//! delivery a run was given and each wait's settled reply is a row-held
//! response of its own (KS-2B1), sealed whole under a body instance, the row
//! its erased form in an image (when it came and the rows its reply was
//! derived from stay, its reply goes).
//!
//! A delivery is its run's: its run, the actor its membership names and the
//! actor its run's stamps name own it, and an erase of any of them retires
//! the instance. A settled reply is shared: every membership of the wait
//! that keeps it owns it (the connector caller's among them), and one
//! holder's erase owes its retirement to the final holder's release, when
//! the settled row takes its erased form ([`super::erase_settled_in_txn`]).
//! A waiter not yet delivered, a cursor and the rows a reply was derived
//! from own nothing. An already-erased row holds no reply to carry. A row
//! that does not decode is carried whole, opaque, and its retired form is
//! the erased marker, which every reader answers as an erased reply (FIX
//! 9390).

use super::super::response_owners::response_owner_in_txn;
use super::super::wait_delivery::{DELIVERIES, SETTLED, SETTLED_TAG, WaitDelivery};
use super::{HOLDERS, WaitHolder};
use crate::side_table::{ErasedForm, SideKey, SideTableDbs};
use crate::store::{ResponseCarriage, ResponseScan, is_opaque_erased};
use crate::{EntityId, Result};

/// The wait a settled row's full `vault_meta` key names: the wait index's
/// `s` rows alone, never a waiter's.
fn settled_wait(key: &[u8]) -> Option<EntityId> {
    let (tag, wait) = key.strip_prefix(SETTLED.decl().prefix)?.split_first()?;
    if *tag != SETTLED_TAG[0] {
        return None;
    }
    EntityId::decode_key(wait)
}

/// Whether the full `vault_meta` key `key` is a wait's settled row.
pub(crate) fn settled_wait_key(key: &[u8]) -> bool {
    settled_wait(key).is_some()
}

/// What a checkpoint carries of a delivery's or a settled reply's row: the
/// whole row, its erased form the stub an image holds in its place. No
/// response for a row already erased; a row that does not decode, or whose
/// erased form does not encode, is carried whole as an opaque response.
pub(crate) fn wait_reply_scan(value: &[u8]) -> ResponseScan {
    let Ok(reply) = DELIVERIES.decode_value(value) else {
        return ResponseScan::opaque_row();
    };
    if reply.erased {
        return ResponseScan::NotResponse;
    }
    match reply.into_erased().and_then(|erased| DELIVERIES.encode_value(&erased)) {
        Ok(stub) => ResponseScan::Decoded(ResponseCarriage::whole(stub)),
        Err(_) => ResponseScan::opaque_row(),
    }
}

/// Whether a delivery's or a settled reply's row `value` is an erased one:
/// its decoded erased form, or the erased marker of one that never decoded.
pub(crate) fn wait_reply_erased(value: &[u8]) -> bool {
    is_opaque_erased(value)
        || DELIVERIES
            .decode_value(value)
            .is_ok_and(|reply: WaitDelivery| reply.erased)
}

/// Who owns the delivery row `key` (a full `vault_meta` key): its run, the
/// actor its membership names, and the actor its run's stamps name.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn wait_delivery_owners(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    key: &[u8],
) -> Result<Vec<EntityId>> {
    let Some((run, wait, generation)) = key
        .strip_prefix(DELIVERIES.decl().prefix)
        .and_then(<(EntityId, EntityId, u64) as SideKey>::decode_key)
    else {
        return Ok(Vec::new());
    };
    let mut owners = vec![run];
    if let Some(WaitHolder::Kept { actor: Some(actor) }) =
        HOLDERS.get_lenient(dbs, txn, &(wait, run, generation))?
    {
        owners.push(actor);
    }
    if let Some(owner) = response_owner_in_txn(dbs, txn, &run)? {
        owners.extend(owner.actor());
    }
    owners.extend(crate::dreamer_runner::program_run_actor_in_txn(
        dbs, txn, &run,
    )?);
    owners.sort_unstable();
    owners.dedup();
    Ok(owners)
}

/// Who holds the settled row `key`'s reply (a full `vault_meta` key): each
/// membership of its wait that keeps it, once, by the actor it names (its
/// run's when it names none; a connector caller's is the caller). An erased
/// membership holds nothing.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn wait_settled_owners(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    key: &[u8],
) -> Result<Vec<EntityId>> {
    let Some(wait) = settled_wait(key) else {
        return Ok(Vec::new());
    };
    let mut owners = Vec::new();
    for row in HOLDERS.iter_raw_from(dbs, txn, wait.as_bytes())? {
        let (key, bytes) = row?;
        if let Ok(WaitHolder::Kept { actor }) = HOLDERS.decode_value(&bytes)
            && let Some((_, holder, _)) = <(EntityId, EntityId, u64) as SideKey>::decode_key(&key)
        {
            owners.push(actor.unwrap_or(holder));
        }
    }
    owners.sort_unstable();
    owners.dedup();
    Ok(owners)
}

/// Whether the settled row `key` (a full `vault_meta` key) still holds its
/// reply live: present and not in its erased form. A row that does not
/// decode still holds it (an opaque reply its holders keep), and the erased
/// marker holds none (FIX 9390).
///
/// # Errors
///
/// Storage errors.
pub(crate) fn settled_reply_held_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    key: &[u8],
) -> Result<bool> {
    let Some(wait) = settled_wait(key) else {
        return Ok(false);
    };
    Ok(SETTLED
        .get_bytes(dbs, txn, &(SETTLED_TAG, wait))?
        .is_some_and(|bytes| {
            !is_opaque_erased(&bytes)
                && !SETTLED
                    .decode_value(&bytes)
                    .is_ok_and(|reply| reply.erased)
        }))
}
