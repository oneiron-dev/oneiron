//! The ambient send an interrupt degrades to (FIX 7962), and what a
//! scheduled send carries beside its schedule context: that alternative and
//! the caller's deadline on to its connector TASK (FIX 7962, 8818), and the
//! sender selection its gate dispatch selects by (FIX 12100).

use serde::{Deserialize, Serialize};

use super::OutboundIntent;
use crate::memory::channel_doors::ChannelSelectionRequest;

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

/// The host's sender-selection question a scheduled send answers: the
/// selection request it asked and the counterparty class it passed
/// explicitly on this send. The send's gate dispatch selects its sender by
/// the vault's selection rules over that request's identity faces
/// ([`ChannelSelectionRequest::send_autonomy`]).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutboundSendSelection {
    pub request: ChannelSelectionRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counterparty_class: Option<String>,
}

/// What a scheduled send carries beside its schedule context. The default
/// carries nothing, as every schedule did before it.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutboundScheduleContinuation {
    /// The caller's deadline, vault clock seconds: past it, the TASK stops
    /// waiting on its provider (FIX 8818). `None` sets no deadline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_at: Option<u64>,
    /// The ambient send the interrupt degrades to (FIX 7962).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ambient_alternative: Option<OutboundAmbientAlternative>,
    /// The sender selection the schedule's gate dispatch selects by (FIX
    /// 12100); it rides no TASK. `None` dispatches as every schedule did
    /// before it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selection: Option<OutboundSendSelection>,
}
