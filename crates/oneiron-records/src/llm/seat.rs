//! Moved from `crates/oneiron/src/llm/seat.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::llm::seat::decisions::SeatPickReadings;
use oneiron_model::llm::ModelId;
use oneiron_model::llm::ReasoningEffort;
pub use oneiron_verb_wire::llm::seat::DescriptionSource;
pub use oneiron_verb_wire::llm::seat::policy::SeatPrecedence;
use oneiron_wake_contract::llm::decision::types::TypedDecision;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DescriptionLine {
    pub source: DescriptionSource,
    pub text: String,
}

/// Kind is part of warm-seat eligibility; a follower never borrows a child seat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeatKind {
    Attempt,
    Child,
    Follower,
}

/// Plain-language choice receipt; retained on the seat even if policies change.
/// Beside the model, effort and why, it keeps the pick's complete typed reads
/// (FIX 9926), carried with the seat on reuse and resume.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeatChoiceReceipt {
    pub model: ModelId,
    pub effort: ReasoningEffort,
    pub why: String,
    pub reused: bool,
    /// Every model-pick read of the birth, in the order asked: one for 64 or
    /// fewer candidates; for more, each round's batch reads, the final last.
    #[serde(default)]
    pub model_decisions: Vec<TypedDecision>,
    /// The effort pick's read; `None` when that pick did not run (a holder
    /// fixed the effort, or the model has one rung).
    #[serde(default)]
    pub effort_decision: Option<TypedDecision>,
}
pub mod decisions;
