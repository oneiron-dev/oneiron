//! Public streaming vocabulary. Stream handles carry no text or authority.
use crate::memory::MemoryError;
use crate::{EntityId, Error};
use serde::{Deserialize, Serialize};

/// Maximum resident handles per vault, including streams currently finalizing.
pub const MAX_MESSAGE_STREAMS: usize = 256;
/// Maximum in-memory UTF-8 text per handle.
pub const MAX_MESSAGE_STREAM_BYTES: usize = 1024 * 1024;
/// Default quiet interval. Hosts must pump independently of token arrival.
pub const DEFAULT_MESSAGE_STREAM_IDLE_MS: u64 = 30_000;

/// Presence publication cadence. Windows count Unicode scalar values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamCadence {
    /// Publish each accepted append.
    PerToken,
    /// Publish when an append ends in terminal punctuation (ignoring whitespace).
    PerSentence,
    /// Publish after this many new Unicode scalars since the preceding publication.
    PerWindow { chars: u32 },
    /// Publish only on an explicit flush.
    Manual,
}
/// Partial-text visibility. Finalized text follows the ordinary record sync lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamSyncVisibility {
    OriginatorOnly,
    AllDevices,
}
/// Atomic is the default; it buffers without publishing partials.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageWriteMode {
    #[default]
    Atomic,
    Streamed {
        visibility: StreamSyncVisibility,
        cadence: StreamCadence,
    },
}
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageStreamHandle {
    pub(super) message: EntityId,
    pub(super) generation: EntityId,
}
impl MessageStreamHandle {
    #[must_use]
    pub fn message_id(&self) -> EntityId {
        self.message
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamFinality {
    Final,
    Partial,
    Cancelled,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamFinalityReason {
    ExplicitFinalize,
    IdleTimeout30s,
    IdleTimeout { timeout_ms: u64 },
    ProcessCrashRecovery,
    UserInterrupted,
    AgentAborted,
    ExternalSignal,
    Custom(String),
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamCancelReason {
    UserInterrupted,
    AgentAborted,
    ExternalSignal,
    Custom(String),
}
/// Durable audit. A crash can recover only previously committed text, never tokens
/// held solely in process memory. The loss flag makes that distinction explicit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageStreamReceipt {
    pub message_id: EntityId,
    /// Original authenticated writer, including unattributed system MESSAGEs.
    pub actor: EntityId,
    pub generation: EntityId,
    pub finality: StreamFinality,
    pub finality_reason: StreamFinalityReason,
    pub bytes: u64,
    pub recovered: bool,
    pub ephemeral_text_lost: bool,
    pub receipt_ref: String,
}
/// Observable local partial. This is never serialized into LMDB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageStreamPartial {
    pub message_id: EntityId,
    pub text: String,
    pub sequence: u64,
    pub mode: MessageWriteMode,
}
/// Stream-specific typed errors; underlying gate errors retain their payload.
#[derive(Debug, thiserror::Error)]
pub enum MessageStreamError {
    #[error("message stream is already active: {0:?}")]
    StreamAlreadyActive(EntityId),
    #[error("unknown, stale or finished message stream")]
    StreamNotFound,
    #[error("message stream belongs to another actor")]
    WrongActor,
    #[error("message stream handle limit reached")]
    TooManyStreams,
    #[error("message stream buffer limit reached")]
    BufferOverflow,
    #[error("message stream presence exceeds the 64 KiB frame budget")]
    PresenceFrameTooLarge,
    #[error("invalid message stream request: {0}")]
    InvalidRequest(&'static str),
    #[error("message stream state lock is poisoned")]
    Poisoned,
    #[error(transparent)]
    Memory(#[from] Box<MemoryError>),
    #[error(transparent)]
    Engine(#[from] Error),
}
impl From<MemoryError> for MessageStreamError {
    fn from(value: MemoryError) -> Self {
        Self::Memory(Box::new(value))
    }
}
impl From<heed::Error> for MessageStreamError {
    fn from(value: heed::Error) -> Self {
        Self::Engine(value.into())
    }
}
pub type MessageStreamResult<T> = std::result::Result<T, MessageStreamError>;
