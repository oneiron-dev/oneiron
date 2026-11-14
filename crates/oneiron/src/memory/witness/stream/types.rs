//! Public streaming vocabulary. Stream handles carry no text or authority.
use crate::EntityId;
use serde::{Deserialize, Serialize};

/// Maximum in-memory UTF-8 text per handle.
pub const MAX_MESSAGE_STREAM_BYTES: usize = 1024 * 1024;
/// Default quiet interval. Hosts must pump independently of token arrival.
pub const DEFAULT_MESSAGE_STREAM_IDLE_MS: u64 = 30_000;

#[doc(hidden)]
pub use oneiron_verb_wire::memory::witness::stream::types::{
    MessageStreamError, MessageStreamPartial, MessageStreamReceipt, MessageStreamResult,
    MessageWriteMode, StreamCadence, StreamFinality, StreamFinalityReason, StreamSyncVisibility,
};

/// Owner-configured defaults. Explicit call mode wins over the actor override.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageStreamPolicy {
    pub default_mode: MessageWriteMode,
    pub agent_overrides: std::collections::BTreeMap<EntityId, MessageWriteMode>,
    /// Independent of the presence TTL. Must be nonzero.
    pub idle_timeout_ms: u64,
}
impl Default for MessageStreamPolicy {
    fn default() -> Self {
        Self {
            default_mode: MessageWriteMode::Atomic,
            agent_overrides: Default::default(),
            idle_timeout_ms: DEFAULT_MESSAGE_STREAM_IDLE_MS,
        }
    }
}
/// An opaque generation-bound handle. Reusing an old handle never edits a successor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MessageStreamHandle {
    pub(super) message: EntityId,
    pub(super) generation: EntityId,
}
impl MessageStreamHandle {
    #[must_use]
    pub fn message_id(&self) -> EntityId {
        self.message
    }
    /// The stream generation this handle writes (FIX 5028): its identity,
    /// read only. A host keys what it keeps for this generation by it before
    /// the stream's call is sent; no caller chooses it.
    #[must_use]
    pub fn generation(&self) -> EntityId {
        self.generation
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamCancelReason {
    UserInterrupted,
    AgentAborted,
    ExternalSignal,
    Custom(String),
}
