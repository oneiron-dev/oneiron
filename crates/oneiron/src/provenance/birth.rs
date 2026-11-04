//! Rule A at row birth: one immutable `made_by` envelope per born row, written
//! beside the row in the transaction that births it (ARCH-0035 Rule A; owner
//! 2026-09-17: "one born-from shape for every generated artifact: summary,
//! lens, code, generated UI, explainer").
//!
//! A row whose text is born as a document carries the same value in its first
//! commit's receipt (`text_commit`, `proposal_text`); this record is the birth
//! of a row that has no document yet. Later commits carry their own receipts,
//! so a row's full provenance is still the fold of its commits.
//!
//! The trigger index reads the born-from ref backwards: a task, ask, run or
//! skill lists the rows it produced (ARCH-0078: "Read that ref backwards and a
//! task has its artifacts").

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::store::Store;
pub(crate) mod checkpoint;
pub(crate) mod prompted;
pub(crate) mod room;

pub use crate::store::row_birth::{
    RoomEvidence, RoomEvidenceRef, RowBirth, WithheldKey, WithheldRef, WithheldRole,
};

pub(crate) use crate::store::birth_record::{
    trigger_is_live_in_txn, run_exists, stamp_row_birth_in_txn, stamp_birth_if_absent_in_txn, stamp_replicated_row_birth_in_txn, row_birth_in_txn, rows_born_from_in_txn, erase_row_birth_in_txn,
};
use crate::store::birth_record::{BIRTH_BY_TRIGGER, ROW_BIRTH};

/// Erasing `actor` (FIX 6074): every birth that names it as its process
/// actor goes, with its born-from index row, in the erase's own transaction,
/// and so does every window carrier of one this vault keeps (FIX 6279). A
/// birth has no erased form (its process names one actor), so the born rows
/// and their content stay and their births read unknown, as a KS-7 restore
/// leaves out a birth whose actor does not open. A born row a legal hold
/// keeps keeps its birth and its carrier (FIX 6280, ARCH-0038: every
/// destructive path checks) until the hold lifts:
/// [`release_held_births_in_txn`] drops them then.
///
/// # Errors
///
/// Storage errors, or a stored birth that does not decode.
pub(crate) fn erase_birth_actor_in_txn(
    vault: &crate::Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let actors = BTreeSet::from([*actor]);
    drop_actor_births_in_txn(vault, wtxn, &actors)?;
    #[cfg(feature = "sync")]
    crate::sync::row_birth::actor_erase::erase_birth_carriers_in_txn(vault, wtxn, &actors)?;
    Ok(())
}

/// The births a legal hold kept from the scrubs of the hard-erased ids
/// `erased`, once nothing holds their rows (FIX 6280): each goes, with its
/// born-from index row, and so does every window carrier of a birth one of
/// them made whose row no hold keeps, whether or not its birth landed here
/// (FIX 6386): a carrier whose row was never born here, or whose stamp was
/// refused, has no local birth to drop first. A row still held keeps both.
///
/// # Errors
///
/// Storage errors, or a stored birth that does not decode.
pub(crate) fn release_held_births_in_txn(
    vault: &crate::Vault,
    wtxn: &mut RwTxn<'_>,
    erased: &BTreeSet<EntityId>,
) -> Result<()> {
    drop_actor_births_in_txn(vault, wtxn, erased)?;
    #[cfg(feature = "sync")]
    crate::sync::row_birth::actor_erase::erase_birth_carriers_in_txn(vault, wtxn, erased)?;
    Ok(())
}

/// Drops each birth whose process actor is in `actors`, but for a born row a
/// legal hold keeps.
fn drop_actor_births_in_txn(
    vault: &crate::Vault,
    wtxn: &mut RwTxn<'_>,
    actors: &BTreeSet<EntityId>,
) -> Result<()> {
    for (row, birth) in ROW_BIRTH.scan(&vault.store, wtxn)? {
        if actors.contains(&birth.made_by.process.actor)
            && !birth_held_in_txn(&vault.store, wtxn, &row)?
        {
            erase_row_birth_in_txn(&vault.store, wtxn, &row)?;
        }
    }
    Ok(())
}

/// Whether a birth one of `actors` made is still stored here: one a legal
/// hold kept from its actor's scrub, or one a lifted hold kept until the
/// next due pass drops it (FIX 6386). An erase of one of `actors` is not
/// complete while one is.
///
/// # Errors
///
/// Storage errors, or a stored birth that does not decode.
pub(crate) fn births_made_by_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    actors: &BTreeSet<EntityId>,
) -> Result<bool> {
    for row in ROW_BIRTH.iter_from(store, txn, &[])? {
        let (_, birth) = row?;
        if actors.contains(&birth.made_by.process.actor) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether a legal hold keeps `row`'s birth: a hold on the row itself or,
/// for a key pad, on its world or a claim its key seals. These are the holds
/// the row's own erase refuses on (`erase_row_provenance_in_txn`), read here
/// as a bool, so an actor's scrub leaves the birth rather than refusing the
/// whole erase (OF-470).
///
/// # Errors
///
/// Storage errors, or a pad body that does not decode.
pub(crate) fn birth_held_in_txn(store: &Store, txn: &RoTxn<'_>, row: &EntityId) -> Result<bool> {
    if crate::store::legal_hold::held_in_txn(store, txn, row.as_bytes())? {
        return Ok(true);
    }
    match store.port_entity_raw(txn, row)? {
        Some(raw) => crate::world_keys::held_pad_world_in_txn(store, txn, &raw),
        None => Ok(false),
    }
}

impl crate::Vault {
    /// `row`'s birth envelope (Rule A), or `None` when none was stamped.
    ///
    /// # Errors
    ///
    /// Storage errors, or a stored envelope that does not decode.
    pub fn row_birth(&self, row: &EntityId) -> Result<Option<RowBirth>> {
        let rtxn = self.store.env.read_txn()?;
        row_birth_in_txn(&self.store, &rtxn, row)
    }

    /// The rows born from `trigger`: a task's, ask's, run's or skill's
    /// artifacts, read through their `made_by` trigger.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn rows_born_from(&self, trigger: &EntityId) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        rows_born_from_in_txn(&self.store, &rtxn, trigger)
    }
}
