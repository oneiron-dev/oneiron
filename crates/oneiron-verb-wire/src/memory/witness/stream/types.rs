//! Moved from `crates/oneiron/src/memory/witness/stream/types.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MemoryError;
use oneiron_model::llm::FinishReason;
use serde::Deserialize;
use serde::Serialize;

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
    #[serde(rename = "idle_timeout_30s")]
    IdleTimeout30s,
    IdleTimeout {
        timeout_ms: u64,
    },
    ProcessCrashRecovery,
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
    pub reply_assertions: oneiron_model::llm::ReplyAssertions,
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
    /// deadline ([`oneiron_base::live_rows::LiveRows`]). Nothing was opened.
    #[error(transparent)]
    WaitedOut(#[from] oneiron_base::live_rows::LiveWaitedOut),
    #[error("message stream buffer limit reached")]
    BufferOverflow,
    #[error("message stream presence frame does not encode")]
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
