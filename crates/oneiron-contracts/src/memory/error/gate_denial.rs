//! The Gate rejection a [`MemoryError`](super::MemoryError) carries when its
//! engine cause was a Gate write rejection.

use serde::{Deserialize, Serialize};

/// The stable Gate rejection strings behind a [`MemoryError`](super::MemoryError) whose engine
/// cause was [`GateError::GateWriteRejected`](crate::error::GateError::GateWriteRejected): the outcome (`pending`/`deny`) and
/// the `gate.*` reason codes, exactly as the engine spelled them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryGateDenial {
    /// `pending` or `deny`.
    pub outcome: String,
    /// Stable `gate.*` reason codes.
    pub reason_codes: Vec<String>,
    /// The ask this refusal raised or found, as its hex ref: a
    /// `gate.deny.message_address` refusal for want of comm reach names the
    /// parent's widen ask here, so no client parses it out of `message`
    /// (FIX 1380). Absent on every other denial.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ask_ref: Option<String>,
    /// While the Gate holds the act for the owner (`pending`), the
    /// approve-once digest his one-time press must name to release it, 64
    /// lower-hex (FIX 6424), copied from the held dispatch's result. Absent
    /// on every other denial.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_digest: Option<String>,
}
