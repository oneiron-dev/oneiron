//! Moved from `crates/oneiron/src/session_lifecycle/speakers.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// One participant bound to a sitting, with the display name it had then.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionParticipant {
    pub actor: EntityId,
    pub display_name: String,
}
