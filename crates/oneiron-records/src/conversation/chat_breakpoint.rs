//! Moved from `crates/oneiron/src/conversation/chat_breakpoint.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The rung a reply's request was captured on, by ref: its provider, its
/// place in the configured ladder, the model its wire names and the digest
/// of the offer it was admitted under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatBreakpointRung {
    pub provider: String,
    pub position: usize,
    pub wire_model: String,
    pub offer_digest: String,
}

/// The user turn a breakpoint's request answers, by the rows its witness
/// wrote (FIX 5033). The request holds its words; no span of the log names
/// them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatBreakpointUserTurn {
    /// The user's TURN.
    pub turn: EntityId,
    /// The MESSAGE rows its words were witnessed into.
    pub messages: Vec<EntityId>,
}
