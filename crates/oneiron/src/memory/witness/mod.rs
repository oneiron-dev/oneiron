//! Witness/turn-ingestion verbs: conversation/turn/message witnessing,
//! off-record session routing, and the turn-speaker wire helpers.
//! Split from the flat `facade.rs`; surface re-exported by [`super`].

mod base;
mod codec;
mod session;
mod types;
mod validation;

pub use self::types::{WitnessAuthor, WitnessMessage, WitnessReceipt, WitnessTurn};

pub(crate) use self::validation::sole_edge_target;

// Helpers the sibling test suite resolves through `use super::witness::*`;
// they keep the flat module's `memory`-level visibility here.
#[cfg(test)]
pub(super) use self::codec::encode_witness_message_body;
pub(super) use self::codec::{decode_witness_turn_speaker, witness_message_envelope};
pub(super) use self::validation::distinct_message_orders;
