//! Witness/turn-ingestion verbs: one witness program (`program`) landing in
//! base (`base`) or in an off-record session overlay (`session`), plus the
//! turn-speaker wire helpers. Surface re-exported by [`super`].

mod base;
mod codec;
mod program;
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
