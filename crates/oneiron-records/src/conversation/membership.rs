//! Moved from `crates/oneiron/src/conversation/membership.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::conversation::*;
pub use crate::memory::conversation_membership::MembershipWindow;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// How much of a room's past a joining member sees.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryChoice {
    /// The room's own rule ([`ConversationBody::shares_history`]): from the
    /// join when the room sets none (ILDF2 P5, "the default is from now").
    #[default]
    Inherit,
    /// The whole past.
    Share,
    /// From the join on.
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipAction {
    Join,
    Leave,
    History,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipRow {
    pub v: u8,
    pub person: EntityId,
    pub action: MembershipAction,
    pub at: u64,
    pub actor: EntityId,
    pub visible_from: Option<u64>,
    /// The exact receipt of the speaker handoff that created this Join.
    pub handoff: Option<SpeakerHandoffReceipt>,
}
