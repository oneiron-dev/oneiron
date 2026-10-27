//! The ambient send an interrupt degrades to (FIX 7962), and what a
//! scheduled send carries on to its connector TASK beside its schedule
//! context: that alternative and the caller's deadline (FIX 7962, 8818).

use serde::{Deserialize, Serialize};

use super::OutboundIntent;

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

/// What a scheduled send carries on to its connector TASK beside its
/// schedule context. The default carries nothing, as every schedule did
/// before it.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutboundScheduleContinuation {
    /// The caller's deadline, vault clock seconds: past it, the TASK stops
    /// waiting on its provider (FIX 8818). `None` sets no deadline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_at: Option<u64>,
    /// The ambient send the interrupt degrades to (FIX 7962).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ambient_alternative: Option<OutboundAmbientAlternative>,
}
