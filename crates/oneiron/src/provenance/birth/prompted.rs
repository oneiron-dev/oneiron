//! A row a model wrote from a prompt that carried other rows (FIX 8192): its
//! birth names each of them as a prompt input, by ref and never by text, so
//! the worlds those rows lie in follow its words wherever they are read or
//! sent ([`prompt_sources_in_txn`]). A row erased since the prompt was built
//! stays named: its words are still in the row ([`prompt_input_held_in_txn`]).
//! A copy masks the ones its destination may not see as handles
//! ([`RowBirth::masked`]), as it masks any input.

use heed::RoTxn;

use super::row_birth_in_txn;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::ManifestDbs;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::write_envelope::provenance::made_by::MadeByInputRole;

/// The rows `row`'s birth names as prompt inputs: the rows a model's prompt
/// carried when it wrote `row`'s words. Empty for a row born with none, or
/// with no birth.
pub(crate) fn prompt_sources_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    row: &EntityId,
) -> Result<Vec<EntityId>> {
    Ok(row_birth_in_txn(store, txn, row)?
        .map(|birth| prompt_sources_of_birth(&birth))
        .unwrap_or_default())
}

/// Prompt inputs named by `birth` itself, with no store read: for a pending
/// birth not yet stamped. Pure; FIX 11000 anchor capture uses it to prove a
/// claim's pending prompt sources from batch state.
pub(crate) fn prompt_sources_of_birth(birth: &RowBirth) -> Vec<EntityId> {
    birth
        .made_by
        .inputs
        .iter()
        .filter(|input| input.role == MadeByInputRole::Prompt)
        .map(|input| input.row)
        .collect()
}

/// Whether `row` may stand as a prompt input of a birth stamped here: a row
/// this vault holds, or one it held and erased, its deletion shell or record
/// still here. An id this vault never held names no row.
pub(crate) fn prompt_input_held_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    row: &EntityId,
) -> Result<bool> {
    if !matches!(
        live_entity_row_in_txn(store, txn, row)?,
        LiveEntityRow::Absent
    ) {
        return Ok(true);
    }
    Ok(crate::ports::TombstoneStoreRead::port_deletion_state(store, txn, row)?.deleted)
}
