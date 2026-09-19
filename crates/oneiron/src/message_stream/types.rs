//! Stream policy, ephemeral frames and durable finality receipts.
use crate::EntityId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MessageWriteMode {
    #[default]
    Atomic,
    Streamed {
        sync_visibility: StreamSyncVisibility,
        cadence: StreamCadence,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamSyncVisibility {
    OriginatorOnly,
    AllDevices,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StreamCadence {
    PerToken,
    PerSentence,
    PerWindow { milliseconds: u32 },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageStreamPolicy {
    pub default_mode: MessageWriteMode,
    /// Keys are validated actor ids, not arbitrary labels.
    pub agent_overrides: BTreeMap<String, MessageWriteMode>,
    pub idle_timeout_ms: u64,
}
impl Default for MessageStreamPolicy {
    fn default() -> Self {
        Self {
            default_mode: MessageWriteMode::Atomic,
            agent_overrides: BTreeMap::new(),
            idle_timeout_ms: 30_000,
        }
    }
}
#[derive(Debug, Clone)]
pub struct MessageStreamHandle {
    pub(super) message: EntityId,
    pub(super) token: EntityId,
    pub(super) mode: MessageWriteMode,
}
impl MessageStreamHandle {
    pub fn message(&self) -> EntityId {
        self.message
    }
    pub fn mode(&self) -> MessageWriteMode {
        self.mode
    }
}
/// Ephemeral presence payload. This type is never persisted by the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageStreamFrame {
    pub message: EntityId,
    pub originator: EntityId,
    pub text: String,
    pub visibility: StreamSyncVisibility,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "description", rename_all = "snake_case")]
pub enum StreamCancelReason {
    UserInterrupted,
    AgentAborted,
    ExternalSignal,
    Custom(String),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageFinality {
    Final,
    Cancelled,
    Partial,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageFinalityReceipt {
    pub(super) receipt_id: String,
    pub(super) message_id: String,
    pub(super) actor_id: String,
    pub(super) finality: MessageFinality,
    pub(super) reason: Option<StreamCancelReason>,
    pub(super) finality_reason: Option<String>,
    pub(super) recorded_at: u64,
    pub(super) text_blake3: String,
}
impl MessageFinalityReceipt {
    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }
    pub fn message_id(&self) -> &str {
        &self.message_id
    }
    pub fn finality(&self) -> MessageFinality {
        self.finality
    }
    pub fn reason(&self) -> Option<&StreamCancelReason> {
        self.reason.as_ref()
    }
    pub fn finality_reason(&self) -> Option<&str> {
        self.finality_reason.as_deref()
    }
    pub fn recorded_at(&self) -> u64 {
        self.recorded_at
    }
    pub fn text_blake3(&self) -> &str {
        &self.text_blake3
    }
}
