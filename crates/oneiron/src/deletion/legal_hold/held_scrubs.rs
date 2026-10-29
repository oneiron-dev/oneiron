//! What a legal hold kept an erase from scrubbing, settled once it lifts
//! (FIX 6386, 7993, 7994).
//!
//! An erase that meets a held row keeps the row whole and goes on: a born
//! row's birth and its window carriers stay behind their actor's `dt:`
//! marker, and a held Gate decision stays behind the scrub the erase owes it
//! (`store::gate_decision`). Every due legal-hold pass settles both in its
//! first transaction, whether or not an owner erase waits: an explicit or
//! automatic host-order lift, an owner's narrowing confirm, a released
//! gate-decision partition and the ordinary maintenance pass alike. What is
//! still owed keeps the erase's overall final row owed
//! (`deletion::receipt_final`): the erase stands, and reads completion
//! pending until then.

use std::collections::BTreeSet;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

impl Vault {
    /// Settles, in the caller's writer, the scrubs held rows kept: the births
    /// and carriers no hold keeps any more, which the `dt:` markers name, and
    /// each Gate decision's owed scrub whose partition no hold keeps. A row
    /// still held stays as it is.
    pub(super) fn settle_held_scrubs_in_txn(&self, txn: &mut heed::RwTxn<'_>) -> Result<()> {
        super::super::actor_fields::rerun_birth_actor_scrubs_in_txn(self, txn)?;
        self.store.settle_gate_scrubs_in_txn(txn)?;
        self.store.settle_owed_staged_erases_in_txn(txn)?;
        Ok(())
    }
}

/// Whether a scrub a legal hold kept is still owed for one of an erase's
/// `entity_ids`: a Gate decision's owed scrub, or a birth or window carrier
/// one of them made. Births are read only while a hold row is kept, standing
/// or released: with none, no birth outlived its actor's scrub.
pub(in crate::deletion) fn held_scrubs_owed_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    entity_ids: &[String],
) -> Result<bool> {
    let ids: BTreeSet<EntityId> = entity_ids
        .iter()
        .filter_map(|hex| EntityId::from_hex(hex).ok())
        .collect();
    if ids.is_empty() {
        return Ok(false);
    }
    let sources: Vec<EntityId> = ids.iter().copied().collect();
    if vault.store.gate_scrubs_owed_in_txn(txn, &sources)? {
        return Ok(true);
    }
    if vault.store.staged_erases_owed_in_txn(txn, &sources)? {
        return Ok(true);
    }
    if crate::store::legal_hold::holds_in_txn(&vault.store, txn)?.is_empty() {
        return Ok(false);
    }
    if crate::provenance::birth::births_made_by_in_txn(&vault.store, txn, &ids)? {
        return Ok(true);
    }
    #[cfg(feature = "sync")]
    let carried =
        crate::sync::row_birth::actor_erase::birth_carriers_remain_in_txn(vault, txn, &ids)?;
    #[cfg(not(feature = "sync"))]
    let carried = false;
    Ok(carried)
}
