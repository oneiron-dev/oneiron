//! Rows a record feeds outside the generic index set, torn with the record.
//!
//! Both delete doors call [`tear_derived_rows_in_txn`]: the physical
//! `deindex_entity` (batch delete, hard purge, replayed hard tombstone) and the
//! soft erase that leaves a shell. Each row family here was added after those
//! doors, so neither reached it (F08).
//!
//! A module whose side tables key rows by an entity whose erase it does not
//! run (a typed body, an artifact's office body or deck) registers one eraser
//! in [`ERASERS`], one line each.
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;

/// Removes the rows one module keys by the erased entity, and is a no-op for
/// an entity it holds nothing for. Runs in the erase transaction, at both
/// delete doors, before the record's body and edges go.
pub(crate) type EntitySideRowEraser = fn(&Store, &mut heed::RwTxn<'_>, &EntityId) -> Result<()>;

/// Every per-entity eraser, one line per module.
const ERASERS: &[EntitySideRowEraser] = &[
    crate::typed_body::erase_in_txn,
    crate::office_body::erase_in_txn,
    crate::edit_roundtrip::deck_create::erase_in_txn,
    crate::memory::erase_stream_seeds_in_txn,
    crate::store::legal_hold::erase_in_txn,
    crate::workspace_roster::erase_room_side_rows,
    crate::task_verb::erase_report_journal_in_txn,
];

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
    for erase in ERASERS {
        erase(store, wtxn, id)?;
    }
    if physical {
        crate::identity_topology::forget_claim_reassignments_in_txn(store, wtxn, id)?;
        crate::identity_redirect::forget_deleted_in_txn(store, wtxn, id)?;
    }
    Ok(())
}
