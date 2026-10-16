//! Rows a record feeds outside the generic index set, torn with the record.
//!
//! Both delete doors call [`tear_derived_rows_in_txn`]: the physical
//! `deindex_entity` (batch delete, hard purge, replayed hard tombstone) and the
//! soft erase that leaves a shell. Each row family here was added after those
//! doors, so neither reached it (F08).
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;

/// Runs before the record's body and edges go. `physical` is false for a soft
/// erase, which keeps the shell's topology (redirects, claim reassignment).
pub(crate) fn tear_derived_rows_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    physical: bool,
) -> Result<()> {
    // The symbol manifest and its revision index name the artifact's symbols
    // (H41).
    crate::code_symbol::delete_code_symbol_manifest_in_txn(store, wtxn, id)?;
    // Both contact index legs carry a hash of the counterparty (H105).
    crate::counterparty_contact::drop_contact_index_rows_in_txn(store, wtxn, id)?;
    if physical {
        crate::identity_topology::forget_claim_reassignments_in_txn(store, wtxn, id)?;
        crate::identity_redirect::forget_deleted_in_txn(store, wtxn, id)?;
    }
    Ok(())
}
