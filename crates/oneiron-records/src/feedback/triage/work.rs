//! Moved from `crates/oneiron/src/feedback/triage/work.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The skill arm a generation runs and the window it was cut for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriagePin {
    /// The SKILL entity the owner bound.
    pub skill: EntityId,
    /// The entity that loaded when the generation was planned: the bound
    /// skill, or the open proposal of it an exploration trial routed to.
    pub entity: EntityId,
    /// The version that loaded; every child loads exactly it.
    pub version: String,
    /// The model whose window the generation was cut for.
    pub model: String,
    /// That window less the output it reserves, in tokens.
    pub input_tokens: u64,
}

/// A byte range of the item text, on character boundaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageSpan {
    /// Its first byte.
    pub start: u64,
    /// One past its last byte.
    pub end: u64,
}
