//! Typed public MESSAGE lifecycle inputs, projected by the verb table.
use super::*;
use crate::memory::{WitnessAssertions, WitnessAuthor};
use serde::{Deserialize, Serialize};

/// The immutable witness axes needed to create a MESSAGE at a caller-chosen id.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MessageBirth {
    pub conversation_ref: String,
    #[serde(default)]
    pub turn_ref: Option<String>,
    pub author: WitnessAuthor,
    pub message_type: String,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    pub is_visible: bool,
    pub order: u32,
    pub occurred_at: u64,
    #[serde(default)]
    pub assertions: WitnessAssertions,
    #[serde(default)]
    pub quote: Option<crate::store::conversation_record::QuoteSpan>,
}

#[doc(hidden)]
pub use oneiron_verb_wire::memory::witness::stream::api_types::{
    MessageCancelKind, MessageCancelReason, MessageCommitOptions, MessageCustomCancel,
    MessageCustomCancelKind, MessageDocumentState, MessageDurability, MessageDurabilityRequest,
    MessageStreamMode, MessageStreamOptions,
};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommitMessageRequest {
    pub message_id: String,
    pub content: String,
    pub birth: MessageBirth,
    #[serde(default)]
    pub options: MessageCommitOptions,
}

/// With birth axes, opens a new MESSAGE; without them, continues the stored one.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BeginMessageStreamRequest {
    pub message_id: String,
    #[serde(default)]
    pub birth: Option<MessageBirth>,
    #[serde(default)]
    pub options: MessageStreamOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MessageStreamRequest {
    pub handle: MessageStreamHandle,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AppendToStreamRequest {
    pub handle: MessageStreamHandle,
    pub delta: String,
}

impl From<MessageCancelReason> for StreamCancelReason {
    fn from(reason: MessageCancelReason) -> Self {
        match reason {
            MessageCancelReason::Named(MessageCancelKind::UserInterrupted) => Self::UserInterrupted,
            MessageCancelReason::Named(MessageCancelKind::AgentAborted) => Self::AgentAborted,
            MessageCancelReason::Named(MessageCancelKind::ExternalSignal) => Self::ExternalSignal,
            MessageCancelReason::Custom(reason) => Self::Custom(reason.description),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CancelStreamRequest {
    pub handle: MessageStreamHandle,
    pub reason: MessageCancelReason,
}
