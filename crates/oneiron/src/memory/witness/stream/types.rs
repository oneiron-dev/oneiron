//! Public streaming vocabulary. Stream handles carry no text or authority.
use crate::EntityId;
use serde::{Deserialize, Serialize};

/// Maximum in-memory UTF-8 text per handle.
pub const MAX_MESSAGE_STREAM_BYTES: usize = 1024 * 1024;
#[doc(hidden)]
pub use oneiron_records::memory::witness::stream::types::{
    DEFAULT_MESSAGE_STREAM_IDLE_MS, MessageStreamPolicy, StreamCancelReason,
};

#[doc(hidden)]
pub use oneiron_verb_wire::memory::witness::stream::types::{
    MessageStreamError, MessageStreamPartial, MessageStreamReceipt, MessageStreamResult,
    MessageWriteMode, StreamCadence, StreamFinality, StreamFinalityReason, StreamSyncVisibility,
};

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
