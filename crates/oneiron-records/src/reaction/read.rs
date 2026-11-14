//! Moved from `crates/oneiron/src/reaction/read.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::claim::reaction_record::ReactionExternalId;
use oneiron_contracts::entity_id::EntityId;

/// One glyph's live reactions, contributors in first-put order.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ReactionPill {
    pub glyph: String,
    pub count: usize,
    pub by: Vec<EntityId>,
    pub mine: bool,
}

/// One claim of a (message, person, glyph) chain.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ReactionHistoryEntry {
    pub id: EntityId,
    pub glyph: String,
    pub by: EntityId,
    pub occurred_at: u64,
    pub recorded_at: u64,
    pub removed_at: Option<u64>,
    pub external_id: Option<ReactionExternalId>,
}
