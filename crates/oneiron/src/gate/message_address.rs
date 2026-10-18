//! FIX 1380: the refusal a `self.message` takes when the comm dial does not
//! admit its address. It is a gate denial with one stable reason code; the
//! dial's own reason rides the message text, never the reason codes. No
//! decision row is kept: the write it refuses rolls back with it.

use crate::error::{Error, GateDenialReason, GateError};
use crate::memory::MemoryError;

/// `FORBIDDEN`, carrying the typed denial `gate.deny.message_address`, with
/// `reason` as its message and `suggestion` as its remedy.
pub(crate) fn message_address_refusal(reason: &str, suggestion: &str) -> MemoryError {
    let code = GateDenialReason::DenyMessageAddress;
    let mut refusal = MemoryError::from(Error::Gate(GateError::GateWriteRejected {
        outcome: code.outcome().as_str(),
        reason_codes: vec![code.as_str()],
    }));
    refusal.message = format!("message address refused: {reason}");
    refusal.suggestions = vec![suggestion.to_owned()];
    refusal
}
