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
    pub quote: Option<crate::conversation_dag::QuoteSpan>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MessageCommitOptions {
    /// The message's prose register, carried in its canonical witness metadata.
    #[serde(default)]
    pub register: Option<String>,
}

/// Canon's tagged per-call mode; the engine resolves omitted modes from policy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MessageStreamMode {
    Atomic,
    Streamed {
        #[serde(rename = "syncVisibility")]
        sync_visibility: StreamSyncVisibility,
        cadence: StreamCadence,
    },
}
impl From<MessageStreamMode> for MessageWriteMode {
    fn from(mode: MessageStreamMode) -> Self {
        match mode {
            MessageStreamMode::Atomic => Self::Atomic,
            MessageStreamMode::Streamed {
                sync_visibility,
                cadence,
            } => Self::Streamed {
                visibility: sync_visibility,
                cadence,
            },
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MessageStreamOptions {
    #[serde(default)]
    pub mode: Option<MessageStreamMode>,
    #[serde(default)]
    pub register: Option<String>,
}

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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MessageCancelKind {
    UserInterrupted,
    AgentAborted,
    ExternalSignal,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MessageCustomCancelKind {
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MessageCustomCancel {
    pub kind: MessageCustomCancelKind,
    pub description: String,
}

/// Canon's string reasons or an explicitly described custom reason.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum MessageCancelReason {
    Named(MessageCancelKind),
    Custom(MessageCustomCancel),
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

/// A bounded page of immutable terminal generations and retained document states.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MessageDurabilityRequest {
    pub message_id: String,
    #[serde(default)]
    pub after_generation: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MessageDocumentState {
    pub frontier: Vec<u8>,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MessageDurability {
    pub message_id: String,
    pub completion: MessageCompletion,
    pub latest_receipt: Option<MessageStreamReceipt>,
    pub receipts: Vec<MessageStreamReceipt>,
    pub next_after_generation: Option<String>,
    pub document_exists: bool,
    /// Retained states of the document's op history, newest first. Empty before birth.
    pub document_history: Vec<MessageDocumentState>,
}
