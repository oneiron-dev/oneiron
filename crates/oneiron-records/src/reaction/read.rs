//! Moved from `crates/oneiron/src/reaction/read.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;

/// One glyph's live reactions, contributors in first-put order. `count`
/// counts every reaction the read admits; `by` lists only the reactors the
/// reader may read, so it can be shorter than `count` (Engine ANSWER
/// REACTION-REACTOR-ID-SURFACES = A, 17 Nov 03:15).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ReactionPill {
    pub glyph: String,
    pub count: usize,
    pub by: Vec<EntityId>,
    pub mine: bool,
}
