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
