//! A replicated row's birth scope, stamped from the carrier its window holds
//! beside it (FIX 3656; Engine ruling 09:39 A), in the savepoint that admitted
//! the row. The record scope judges the carrier; one that does not hold
//! leaves the row unstamped, never refused.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::vault::{LiveEntityRow, Vault, live_entity_row_in_txn};

/// Stamps the live row `id` at the birth scope `doc` carries for it, read in
/// `txn`, when it holds no stamp of its own.
pub(super) fn stamp_carried_birth_scope_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    doc: &loro::LoroDoc,
    id: &EntityId,
) -> Result<()> {
    let Some(carried) = crate::sync::window::birth_scope::carried(doc, id) else {
        return Ok(());
    };
    let LiveEntityRow::Live { entity_type, .. } = live_entity_row_in_txn(&vault.store, txn, id)?
    else {
        return Ok(());
    };
    crate::federation::record_scope::stamp_carried_birth_scope_in_txn(
        &vault.store,
        txn,
        *id,
        entity_type,
        &carried,
    )?;
    Ok(())
}
