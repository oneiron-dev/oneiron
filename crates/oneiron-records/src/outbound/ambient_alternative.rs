//! Moved from `crates/oneiron/src/outbound/ambient_alternative.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::outbound::intent::OutboundIntent;
use serde::Deserialize;
use serde::Serialize;

/// A host-selected ambient send: the surface the delivery window degrades
/// the interrupt to, and the full send that carries it there, with its own
/// channel, verb, target and content. Its actor is the interrupt's actor.
/// The engine never derives one from the interrupt's own target or from the
/// surface's name.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutboundAmbientAlternative {
    pub surface: String,
    pub intent: OutboundIntent,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counterparty_ref: Option<String>,
}
