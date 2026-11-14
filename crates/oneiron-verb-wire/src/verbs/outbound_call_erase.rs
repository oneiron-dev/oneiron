//! Moved from `crates/oneiron/src/verbs/outbound_call_erase.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// `vault.outbound_calls.request.erase`'s input: the call's attempt and its
/// sequence within that attempt.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OutboundCallRequestEraseRequest {
    /// The call's attempt, 32 hex.
    pub attempt: EntityId,
    pub call_seq: u64,
}

/// `vault.outbound_calls.request.erase`'s answer: `false` for a call with no
/// row here, or one whose request is already erased.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OutboundCallRequestErased {
    pub erased: bool,
}
