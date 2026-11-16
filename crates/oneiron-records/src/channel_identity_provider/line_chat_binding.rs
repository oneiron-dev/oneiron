//! Moved from `crates/oneiron/src/channel_identity_provider/line_chat_binding.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::channel_identity_provider::inbound_types::LineChat;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// One LINE group or room the bot was seen in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineChatObservation {
    /// The bot (the webhook `destination`) the chat was seen on.
    pub destination: String,
    pub chat: LineChat,
    /// When the chat was first seen, Unix seconds at receipt.
    pub observed_at: u64,
    /// The archived provider event that first showed it.
    pub payload_ref: String,
}

/// An optional offer to bind one observed chat to an agent. Accepting it
/// provisions the chat's own route key through the owner's provision door.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineChatBindingOffer {
    /// The observation an accept names.
    pub observation_ref: EntityId,
    pub observation: LineChatObservation,
    /// The chat's own route key on the bot: what a bind provisions.
    pub address_or_handle: String,
    /// The identity that already holds that route key, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_identity_ref: Option<EntityId>,
}
