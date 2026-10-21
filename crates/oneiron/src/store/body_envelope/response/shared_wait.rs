//! A wait's settled reply, shared by every holder of the wait (FIX 6588,
//! KEY STORE = A): one holder's erase never retires the instance older
//! images carry it under while another holder still keeps the reply.
//!
//! The erase owes the retirement instead, in the same debt a shared body's
//! erase owes ([`ERASE_PENDING`]), so the finisher's readiness, the
//! retention policy and the custody status wait on it alike, and the receipt
//! names it. The final holder's release, when the settled row takes its
//! erased form by any door, stages it then. A release no erase owes keeps
//! the key: a delete or a scrub never creates an erase cause. A holder that
//! joins a settled reply after it was bound joins every obligation of the
//! instance it rests under, at the next binding pass.

use heed::{RoTxn, RwTxn};

use super::super::retention::{ERASE_PENDING, ErasedNotes, stage_erase};
use super::{
    RESPONSE_OWNERS, ResponseDb, ResponseFamily, carrier_row, release_response_in_txn,
    response_binding_in_txn,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{SideKey, SideTableDbs};
use crate::store::ManifestDbs;

/// Whether the row `carrier` names is of a shared family.
fn shared(carrier: &[u8]) -> bool {
    carrier_row(carrier).is_some_and(|(db, key)| {
        db == ResponseDb::VaultMeta && crate::code_run::settled_wait_key(key)
    })
}

/// Whether another holder still keeps the shared reply `carrier` names
/// under `instance`, the erasing owner's obligation already gone: its live
/// row still holds the reply, and another owner's obligation names the
/// instance. Never for a family that is not shared.
///
/// # Errors
///
/// Storage errors.
pub(super) fn still_held<D: SideTableDbs>(
    dbs: &D,
    txn: &RoTxn<'_>,
    carrier: &[u8],
    instance: &[u8; 16],
) -> Result<bool> {
    let Some((_, key)) = carrier_row(carrier).filter(|_| shared(carrier)) else {
        return Ok(false);
    };
    if !crate::code_run::settled_reply_held_in_txn(dbs, txn, key)? {
        return Ok(false);
    }
    for row in RESPONSE_OWNERS.iter_raw_from(dbs, txn, &[])? {
        let (key, _) = row?;
        if <(EntityId, [u8; 16]) as SideKey>::decode_key(&key)
            .is_some_and(|(_, held)| held == *instance)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Owes `instance`'s retirement to the final holder's release, noted for
/// `owner`'s receipt.
///
/// # Errors
///
/// Storage errors.
pub(super) fn owe<D: SideTableDbs>(
    dbs: &D,
    wtxn: &mut RwTxn<'_>,
    (owner, notes): (&EntityId, &mut ErasedNotes),
    carrier: &[u8],
    instance: &[u8; 16],
) -> Result<()> {
    let digest = response_binding_in_txn(dbs, wtxn, carrier)?
        .filter(|binding| binding.instance == *instance)
        .map_or([0; 32], |binding| binding.digest);
    ERASE_PENDING.put(dbs, wtxn, instance, &digest)?;
    notes.note(dbs, wtxn, owner, instance)
}

/// Drops a debt an earlier holder's erase owed `instance`: its retirement
/// is staged now.
///
/// # Errors
///
/// Storage errors.
pub(super) fn discharge<D: SideTableDbs>(
    dbs: &D,
    wtxn: &mut RwTxn<'_>,
    instance: &[u8; 16],
) -> Result<()> {
    ERASE_PENDING.delete(dbs, wtxn, instance)?;
    Ok(())
}

/// The final release of the shared reply the row `carrier` names, by any
/// door, in its transaction: when an erase owes its instance, the intent is
/// staged now and its binding goes. Nothing else: a release no erase owes
/// keeps the key.
///
/// # Errors
///
/// Storage and custody errors.
pub(crate) fn settle_shared_response_in_txn<D: ManifestDbs + SideTableDbs>(
    dbs: &D,
    wtxn: &mut RwTxn<'_>,
    carrier: &[u8],
) -> Result<()> {
    let Some(binding) = response_binding_in_txn(dbs, wtxn, carrier)? else {
        return Ok(());
    };
    if !ERASE_PENDING.delete(dbs, wtxn, &binding.instance)? {
        return Ok(());
    }
    release_response_in_txn(dbs, wtxn, carrier)?;
    let mut notes = ErasedNotes::default();
    stage_erase(dbs, wtxn, (None, &mut notes), &binding.instance)?;
    notes.journal(dbs)
}

/// Whether every one of `owners` holds an obligation naming `instance`: a
/// shared family's late holder that holds none yet joins it at the next
/// binding pass. Any other family: always.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn response_owed_to_all_in_txn<D: SideTableDbs>(
    dbs: &D,
    txn: &RoTxn<'_>,
    family: ResponseFamily,
    instance: &[u8; 16],
    owners: &[EntityId],
) -> Result<bool> {
    if !family.shared() {
        return Ok(true);
    }
    for owner in owners {
        if !RESPONSE_OWNERS.contains(dbs, txn, &(*owner, *instance))? {
            return Ok(false);
        }
    }
    Ok(true)
}
