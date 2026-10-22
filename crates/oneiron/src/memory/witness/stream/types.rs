//! Public streaming vocabulary. Stream handles carry no text or authority.
use crate::memory::MemoryError;
use crate::{EntityId, Error, FinishReason};
use serde::{Deserialize, Serialize};

/// Maximum in-memory UTF-8 text per handle.
pub const MAX_MESSAGE_STREAM_BYTES: usize = 1024 * 1024;
/// Default quiet interval. Hosts must pump independently of token arrival.
pub const DEFAULT_MESSAGE_STREAM_IDLE_MS: u64 = 30_000;

/// Presence publication cadence. Windows count Unicode scalar values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StreamSyncVisibility {
    OriginatorOnly,
    AllDevices,
}
/// Atomic is the default; it buffers without publishing partials.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
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
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StreamFinality {
    Final,
    Partial,
    Cancelled,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
/// Durable audit. A crash recovers the stream's last checkpoint: every accepted
/// delta is saved in its seed before it is published, so the loss flag is set
/// only when accepted text was ahead of that checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MessageStreamReceipt {
    pub message_id: EntityId,
    /// Original authenticated writer, including unattributed system MESSAGEs.
    pub actor: EntityId,
    pub generation: EntityId,
    pub finality: StreamFinality,
    pub finality_reason: StreamFinalityReason,
    /// Why the model that wrote this generation stopped; `None` from a writer
    /// that is no model, an idle expiry and a crash recovery.
    pub finish_reason: Option<FinishReason>,
    pub bytes: u64,
    pub recovered: bool,
    pub ephemeral_text_lost: bool,
    pub receipt_ref: String,
    /// The records this generation's reply asserts it cited or created
    /// (FIX 10258, FIX 10260): its stream's seed set and its terminal's, a
    /// Continue's too, each by the registry type its row has and its id, as
    /// admitted in the write that saved this generation, where each was read
    /// through the writer's own lane (OF-063). Readability, not proof that
    /// the writer made a record it names as `created`. Empty for one that
    /// asserts none, and on a receipt kept before them; an erase of its
    /// MESSAGE takes them off.
    #[serde(default)]
    pub reply_assertions: crate::llm::ReplyAssertions,
}
/// Observable local partial. This is never serialized into LMDB.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
    /// The stream waited for its turn past the vault's live row and its
    /// deadline ([`crate::live_rows::LiveRows`]). Nothing was opened.
    #[error(transparent)]
    WaitedOut(#[from] crate::live_rows::LiveWaitedOut),
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
