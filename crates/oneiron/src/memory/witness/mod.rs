//! Witness/turn-ingestion verbs: one witness program (`program`) landing in
//! base (`base`) or in an off-record session overlay (`session`), plus the
//! turn-speaker wire helpers. Surface re-exported by [`super`].

mod base;
mod codec;
mod program;
mod session;
mod stream;
mod types;
pub use stream::*;
pub(crate) use stream::{MessageStreamRuntime, message_stream_finality_in_txn};
mod validation;

pub use self::types::{WitnessAuthor, WitnessMessage, WitnessReceipt, WitnessTurn};

pub(crate) use self::codec::{IMPORTED_SOURCE_KEY, guard_import_stamp, witness_message_body};
pub(crate) use self::program::ImportedTurnStamp;

pub(crate) use self::validation::{next_witness_message_order, sole_edge_target};

// Helpers the sibling test suite resolves through `use super::witness::*`;
// they keep the flat module's `memory`-level visibility here.
pub(super) use self::codec::decode_witness_turn_speaker;
#[cfg(test)]
pub(super) use self::codec::encode_witness_message_body;
use self::codec::witness_message_envelope;
pub(super) use self::validation::distinct_message_orders;

fn person_author_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    actor: crate::EntityId,
) -> super::MemoryResult<Option<crate::EntityId>> {
    let kind = vault
        .get_raw_in(txn, &actor)?
        .map(|raw| {
            crate::batch::EntityMetadataHeader::parse(&raw)
                .ok_or(crate::Error::CorruptedIndex("witness actor header"))
        })
        .transpose()?
        .map(|header| header.entity_type);
    Ok((kind == Some(crate::registry::ENTITY_TYPE_PERSON)).then_some(actor))
}

fn reject_erased_person_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    room: crate::EntityId,
    person: Option<crate::EntityId>,
) -> super::MemoryResult<()> {
    // Check in this writer snapshot; a failed lookup must not allow admission.
    if let Some(person) = person
        && !crate::conversation::room_person_write_allowed(&vault.store, txn, room, person)?
    {
        return Err(super::MemoryError::bad_request(
            "erased person cannot witness a turn in this room",
        ));
    }
    Ok(())
}
