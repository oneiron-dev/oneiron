//! An erase's reach into the cloud registration (L04 08:3x, FIX 9056): the
//! `CLOUD_REGISTRATION` table's actor scrub, which every hard erase runs in
//! its own transaction (`side_table::decls`, FIX 3520), and what it hands
//! the erase's receipt.
//!
//! An erase of an owner takes every slot that owner linked, current,
//! replaced or logged out, as the owner's own erase of the registration
//! does: each fenced, every key its id names staged to retire, and its
//! record, name and row erased; a slot the owner's erase left `Erasing`
//! loses its row. Those slots bind on the erase's receipt as erased with
//! it (`deletion::receipt`), so its final row waits on their keys too. An
//! erase of a slot's own record, which that erase fences itself, takes the
//! slot's row. A delete runs no scrub and keeps them all.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use heed::RwTxn;

use super::store::{erase_slot_in_txn, rows_in_txn};
use super::{CloudRegistrationPhase, ROWS};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

thread_local! {
    /// The slots this thread's erases took with each erased owner, until
    /// the erase's receipt reads them in the same transaction.
    static TAKEN: RefCell<BTreeMap<EntityId, BTreeSet<EntityId>>> =
        const { RefCell::new(BTreeMap::new()) };
}

/// The cloud registration's actor scrub (FIX 3520): `id`'s erase in `wtxn`.
/// Every slot `id` linked is erased with it; the row of a slot whose own
/// record is `id` goes.
///
/// # Errors
/// A legal hold on a slot, which refuses the erase; storage faults.
pub(crate) fn erase_cloud_registration_actor_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let mut taken = BTreeSet::new();
    for (slot, row) in rows_in_txn(&vault.store, &*wtxn)? {
        if slot == *id {
            // The erase of the record itself fenced it before this scrub.
            ROWS.delete(&vault.store, wtxn, &slot)?;
        } else if row.owner == *id {
            // An owner's erase of the registration fenced an `Erasing`
            // slot already; fencing it again would reopen its discovery.
            if row.phase != CloudRegistrationPhase::Erasing {
                erase_slot_in_txn(vault, wtxn, &slot)?;
            }
            ROWS.delete(&vault.store, wtxn, &slot)?;
            taken.insert(slot);
        }
    }
    if !taken.is_empty() {
        TAKEN.with(|held| held.borrow_mut().entry(*id).or_default().extend(taken));
    }
    Ok(())
}

/// The slots an erase of `holder` took in this thread, for its receipt to
/// bind as erased with it; each is handed over once.
pub(crate) fn cloud_registration_erased_with(holder: &EntityId) -> Vec<EntityId> {
    TAKEN.with(|held| {
        held.borrow_mut()
            .remove(holder)
            .map(|slots| slots.into_iter().collect())
            .unwrap_or_default()
    })
}
