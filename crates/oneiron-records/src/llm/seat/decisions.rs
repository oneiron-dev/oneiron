//! Moved from `crates/oneiron/src/llm/seat/decisions.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_wake_contract::llm::decision::types::TypedDecision;
use serde::Deserialize;
use serde::Serialize;

/// The pick's complete typed reads (FIX 9926): every model-pick decision in
/// the order asked (one for 64 or fewer candidates; for more, each round's
/// batch reads, the final one last), and the effort decision when that pick
/// ran.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeatPickReadings {
    pub model_decisions: Vec<TypedDecision>,
    pub effort_decision: Option<TypedDecision>,
}
