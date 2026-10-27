//! A row a model wrote from a prompt that carried other rows (FIX 8192): its
//! birth names each of them as a prompt input, by ref and never by text, so
//! the worlds those rows lie in follow its words wherever they are read or
//! sent ([`prompt_sources_in_txn`]). A row erased since the prompt was built
//! stays named: its words are still in the row ([`prompt_input_held_in_txn`]).
//! A copy masks the ones its destination may not see as handles
//! ([`RowBirth::masked`]), as it masks any input.

use heed::RoTxn;

use super::{RowBirth, row_birth_in_txn};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::provenance::made_by::{MadeByClass, MadeByInputRole};
use crate::store::ManifestDbs;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::write_envelope::WriteActor;

impl RowBirth {
    /// The birth of a row `actor` wrote through `door` at `at`, made of a
    /// model's answer to a prompt that carried the rows `prompt` (each named
    /// once, in order), whose bytes as the model read them are `read`.
    /// `None` when the prompt carried no row: the row keeps the birth its
    /// writer gives it.
    pub(crate) fn prompted(
        actor: WriteActor,
        class: MadeByClass,
        door: &str,
        prompt: &[EntityId],
        read: &[&[u8]],
        at: u64,
    ) -> Option<Self> {
        if prompt.is_empty() {
            return None;
        }
        let mut birth = Self::written(actor, class, door, prompt, read, at)?;
        for input in &mut birth.made_by.inputs {
            input.role = MadeByInputRole::Prompt;
        }
        Some(birth)
    }
}

/// The rows `row`'s birth names as prompt inputs: the rows a model's prompt
/// carried when it wrote `row`'s words. Empty for a row born with none, or
/// with no birth.
pub(crate) fn prompt_sources_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    row: &EntityId,
) -> Result<Vec<EntityId>> {
    Ok(row_birth_in_txn(store, txn, row)?
        .map(|birth| {
            birth
                .made_by
                .inputs
                .into_iter()
                .filter(|input| input.role == MadeByInputRole::Prompt)
                .map(|input| input.row)
                .collect()
        })
        .unwrap_or_default())
}

/// Whether `row` may stand as a prompt input of a birth stamped here: a row
/// this vault holds, or one it held and erased, its deletion shell or record
/// still here. An id this vault never held names no row.
pub(crate) fn prompt_input_held_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    row: &EntityId,
) -> Result<bool> {
    if !matches!(live_entity_row_in_txn(store, txn, row)?, LiveEntityRow::Absent) {
        return Ok(true);
    }
    Ok(crate::ports::TombstoneStoreRead::port_deletion_state(store, txn, row)?.deleted)
}
