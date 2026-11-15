//! Moved from `crates/oneiron/src/memory/witness/stream/types.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::memory::witness::stream::types::MessageStreamError;
pub use oneiron_verb_wire::memory::witness::stream::types::MessageStreamPartial;
pub use oneiron_verb_wire::memory::witness::stream::types::MessageStreamReceipt;
pub use oneiron_verb_wire::memory::witness::stream::types::MessageStreamResult;
pub use oneiron_verb_wire::memory::witness::stream::types::MessageWriteMode;
pub use oneiron_verb_wire::memory::witness::stream::types::StreamCadence;
pub use oneiron_verb_wire::memory::witness::stream::types::StreamFinality;
pub use oneiron_verb_wire::memory::witness::stream::types::StreamFinalityReason;
pub use oneiron_verb_wire::memory::witness::stream::types::StreamSyncVisibility;
use serde::Deserialize;
use serde::Serialize;

/// Default quiet interval. Hosts must pump independently of token arrival.
pub const DEFAULT_MESSAGE_STREAM_IDLE_MS: u64 = 30_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamCancelReason {
    UserInterrupted,
    AgentAborted,
    ExternalSignal,
    Custom(String),
}
