//! Moved from `crates/oneiron/src/calendar/prep/pack.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The three ranked sections of a prep pack.
///
/// Declaration order IS the precedence rule, and `Ord` is derived from it: prior
/// commitments first, recent threads with those people second, dossier or
/// company delta third.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PrepSectionKind {
    /// Commitments involving the meeting or its attendees.
    PriorCommitment,
    /// Recent threads with the people in the meeting.
    AttendeeThread,
    /// Dossier or company delta about those people and their orgs.
    DossierDelta,
}

/// One row of prep evidence, with the vault rows that back it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PrepItem {
    /// Which section this row ranks into.
    pub kind: PrepSectionKind,
    /// The row's own text, as stored. Truncated only by the word ceiling.
    pub text: String,
    /// Hex ids of the vault rows this text came from. Never empty.
    pub source_refs: Vec<String>,
    /// When the vault learned the backing row, unix seconds UTC.
    pub observed_at: u64,
}

/// One ranked section of a pack. Empty sections are dropped, never rendered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PrepSection {
    /// Which section this is.
    pub kind: PrepSectionKind,
    /// Rows, most recently learned first inside the section.
    pub items: Vec<PrepItem>,
}

/// One meeting's assembled prep pack.
///
/// Structured data only: no prose, no persona, no localized text. It is a value
/// returned to the caller and never an entity, a claim, or a cache row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PrepPack {
    /// Hex id of the EVENT this pack is about.
    pub event_ref: String,
    /// The fire instant the pack was assembled at, unix seconds UTC.
    pub built_at: u64,
    /// Ranked sections, never empty when a pack exists at all.
    pub sections: Vec<PrepSection>,
    /// Words kept after the ceiling. Never above [`PrepPolicy::max_words`].
    pub word_count: usize,
}
