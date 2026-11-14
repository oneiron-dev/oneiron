//! Moved from `crates/oneiron/src/conversation/speaker_handoff.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::conversation::*;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// Where a handed-off speaker's new PERSON window is visible from.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpeakerHandoffBoundary {
    /// From the join on: the membership door's own boundary.
    #[default]
    JoinTime,
    /// From the speaker's entry: the entry's cut carries into the window.
    EntryEnteredAt,
}

/// What a handoff did, retained on the new membership's ledger row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpeakerHandoffReceipt {
    pub entry_ref: EntityId,
    pub container: EntityId,
    /// The contact the owner named the speaker.
    pub contact: EntityId,
    pub person: EntityId,
    /// The boundary the caller picked.
    pub boundary: SpeakerHandoffBoundary,
    /// When the PERSON's new window is visible from.
    pub visible_from: u64,
    /// When the PERSON joined.
    pub joined_at: u64,
}
