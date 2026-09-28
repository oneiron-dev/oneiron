//! Witness/turn-ingestion verbs: conversation/turn/message witnessing,
//! off-record session routing, and the turn-speaker wire helpers.
//! Split from the flat `facade.rs`; surface re-exported by [`super`].

mod base;
mod codec;
mod session;
mod stream;
mod types;
pub(crate) use stream::MessageStreamRuntime;
pub use stream::*;
mod validation;

pub use self::types::{WitnessAuthor, WitnessMessage, WitnessReceipt, WitnessTurn};

pub(crate) use self::validation::sole_edge_target;

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

/// A receipt type is host-owned, not an extra vocabulary choice for callers.
fn validate_witness_origin(turn: &WitnessTurn, host_executor: bool) -> super::MemoryResult<()> {
    if !host_executor
        && turn.messages.iter().any(|message| {
            message.message_type == crate::code_run::blocked::BLOCKED_REPORT_MESSAGE_TYPE
        })
    {
        return Err(super::MemoryError::bad_request(
            "report-blocked receipts require the executor door",
        ));
    }
    Ok(())
}
