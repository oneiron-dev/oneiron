//! Moved from `crates/oneiron/src/context_board/plugin/state.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_verb_wire::context_board::plugin::manifest::SectionId;
use serde::Deserialize;
use serde::Serialize;

/// The implemented durable block kinds: plugin board state, not the session pad.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoardBlockKind {
    Scratchpad,
}

/// Stored revision of an actor-owned block, returned after commit and on read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoardBlockRecord {
    pub schema_version: u16,
    pub block_ref: [u8; 16],
    pub section_id: SectionId,
    pub kind: BoardBlockKind,
    pub author_ref: [u8; 16],
    pub source_revision_ref: [u8; 16],
    pub markdown: String,
}
