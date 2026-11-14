//! Moved from `crates/oneiron/src/memory/witness/stream/api_types.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::witness::stream::*;
pub use oneiron_verb_wire::memory::witness::stream::api_types::MessageCancelKind;
pub use oneiron_verb_wire::memory::witness::stream::api_types::MessageCancelReason;
pub use oneiron_verb_wire::memory::witness::stream::api_types::MessageCommitOptions;
pub use oneiron_verb_wire::memory::witness::stream::api_types::MessageCustomCancel;
pub use oneiron_verb_wire::memory::witness::stream::api_types::MessageCustomCancelKind;
pub use oneiron_verb_wire::memory::witness::stream::api_types::MessageDocumentState;
pub use oneiron_verb_wire::memory::witness::stream::api_types::MessageDurability;
pub use oneiron_verb_wire::memory::witness::stream::api_types::MessageDurabilityRequest;
pub use oneiron_verb_wire::memory::witness::stream::api_types::MessageStreamMode;
pub use oneiron_verb_wire::memory::witness::stream::api_types::MessageStreamOptions;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;

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
