//! Moved from `crates/oneiron/src/dreamer_wake/sieve/mod.rs` (core split slice 3: wake contract below core).
//! `oneiron` re-exports each item at its old path.

use crate::dreamer_wake::sieve::rules::RuleClass;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// What a span is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanKind {
    Date,
    Name,
}

/// What flagged a span.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanOrigin {
    /// A rule of the given rules version.
    Rule { rules: u32, class: RuleClass },
    /// The turn's saved tag set: the mention at `index`, under the tag set's
    /// envelope as BLAKE3 `envelope`. The label and links stay in the tag set.
    SavedTag { envelope: [u8; 32], index: u64 },
}

/// Where a span's confidence falls on the policy row's band.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanBand {
    Low,
    Uncertain,
    Sure,
}

/// A model rung a span still waits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SieveRung {
    /// What is new here, and of what kind (the NER question).
    Novelty,
    /// The uncertain band's typed question.
    Typing,
}

/// One queued span.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SieveSpan {
    /// BLAKE3 identity of the span's reading: its ref, kind, origin and the
    /// digest of the text it indexes.
    pub id: [u8; 32],
    pub turn: EntityId,
    /// The MESSAGE whose text the offsets index, or the TURN for body text.
    pub source: EntityId,
    /// Byte offsets into that text, whole at any length (Rule 5).
    pub start: u64,
    pub end: u64,
    pub kind: SpanKind,
    /// A model-confirmed existing entity; unresolved spans remain topics.
    pub entity: Option<EntityId>,
    pub novel: Option<bool>,
    pub origin: SpanOrigin,
    /// BLAKE3 of the source text the offsets index.
    pub source_digest: [u8; 32],
    /// BLAKE3 of the policy row that scored the span.
    pub policy_digest: [u8; 32],
    /// Percent.
    pub confidence: u8,
    pub score: u32,
    pub band: SpanBand,
    pub owed: Vec<SieveRung>,
    pub queued_at: u64,
}
pub mod audit_windows;
pub mod recipes;
pub mod rules;
