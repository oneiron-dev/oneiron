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
use super::super::wait_delivery::DELIVERIES;
use super::{HOLDERS, WaitHolder};
use crate::side_table::{SideKey, SideTableDbs};
use crate::{EntityId, Result};

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
