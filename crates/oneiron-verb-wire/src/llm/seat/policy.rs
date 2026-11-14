//! Moved from `crates/oneiron/src/llm/seat/policy.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::llm::seat::DescriptionSource;
use oneiron_model::llm::ReasoningEffort;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SeatPrecedence {
    /// Each authored level (global, purpose, vault, then the holder or judge)
    /// may only narrow its nearest authored parent.
    NarrowOnly,
    /// The most specific authored level wins and a holder may choose another
    /// allowed rung; every level stays under the vault ceiling.
    SeatOverride,
}

pub fn effort_rank(effort: ReasoningEffort) -> u8 {
    match effort {
        ReasoningEffort::None => 0,
        ReasoningEffort::Low => 1,
        ReasoningEffort::Medium => 2,
        ReasoningEffort::High => 3,
        ReasoningEffort::XHigh => 4,
    }
}

/// Source identities are substrate (listed here as a set); their ranking is
/// policy. A valid order names each source exactly once so no line is dropped.
pub fn valid_evidence_order(order: &[DescriptionSource]) -> bool {
    [
        DescriptionSource::Benchmarks,
        DescriptionSource::Measured,
        DescriptionSource::Owner,
        DescriptionSource::Vendor,
    ]
    .iter()
    .all(|source| order.iter().filter(|item| *item == source).count() == 1)
}
