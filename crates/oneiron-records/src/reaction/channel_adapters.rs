//! Moved from `crates/oneiron/src/reaction/channel_adapters.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Serialize;

/// Classic iMessage associated-message types, in provider code order.
pub const IMESSAGE_TAPBACK_GLYPHS: [&str; 6] = ["❤️", "👍", "👎", "😂", "‼️", "❓"];

/// The bridge resolves `message` to its provider message/part handle before
/// execution. No message text or credentials are copied into the queue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IMessageTapbackOperation {
    pub reaction: EntityId,
    pub message: EntityId,
    pub by: EntityId,
    pub associated_message_type: u16,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ReactionChannelCapability {
    pub connector: String,
    pub send: bool,
    pub receive: bool,
    pub emoji_vocabulary: Option<serde_json::Value>,
}
