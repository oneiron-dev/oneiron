//! Moved from `crates/oneiron/src/conversation/attendee.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// Who entered a container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerAttendee {
    /// A PERSON entering as a room member.
    Person(EntityId),
    /// A voice speaker no room member covers, by its stable keys: one the
    /// vault cannot place yet, or one it placed who is no member.
    Speaker {
        session_key: String,
        speaker_key: String,
    },
}
