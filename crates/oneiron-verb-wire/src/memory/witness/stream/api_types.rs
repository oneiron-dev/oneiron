//! Moved from `crates/oneiron/src/memory/witness/stream/api_types.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::witness::stream::*;
use serde::Deserialize;
use serde::Serialize;

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
    /// The reply assertions a MESSAGE born whole kept from its witness write
    /// (FIX 10260); `None` for one that asserted none or was streamed, whose
    /// receipts keep theirs.
    #[serde(default)]
    pub birth_assertions: Option<crate::memory::witness::reply_assertions::MessageReplyAssertions>,
}
