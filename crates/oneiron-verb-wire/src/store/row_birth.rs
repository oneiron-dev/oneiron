//! Moved from `crates/oneiron/src/store/row_birth.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Most hex characters a birth's input hash may carry.
pub const MAX_CONTENT_HASH_HEX: usize = 128;

/// Hex characters of a withheld ref's keyed hash in its handle, after `wh_`
/// (64 bits; an open call in engine-calls-review/CALLS.md, "OF-491 Q26
/// handles").
pub const WITHHELD_HANDLE_HEX: usize = 16;

/// The evidence refs a room write's caller named, each with what the room
/// read it as (FIX 4281, Engine 10-22). A ref the room did not read as a
/// TURN is kept as supplied: the room accepts it, and it is no evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomEvidence {
    /// Every supplied ref, in the order given.
    pub refs: Vec<RoomEvidenceRef>,
}

/// One supplied evidence ref of a room write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomEvidenceRef {
    /// The ref as the caller spelled it.
    pub supplied: String,
    /// The 32 hex digits of the TURN the caller read it as in the room, one
    /// of the birth's inputs; `None` for a ref the room read as no TURN.
    pub turn: Option<String>,
}

/// A ref a birth names that its copy's destination may not see (Q26 = B): a
/// handle in its place, never the ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WithheldRef {
    /// `wh_` and 16 hex of the ref keyed by the copy's [`WithheldKey`]: one
    /// ref reads as one handle within a copy, and the handle never reverses.
    pub handle: String,
    pub role: WithheldRole,
}

/// What a withheld ref was in the birth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WithheldRole {
    Input,
    Prompt,
    Trigger,
}
