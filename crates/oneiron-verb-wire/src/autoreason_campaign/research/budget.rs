//! Moved from `crates/oneiron/src/autoreason_campaign/research/budget.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::research_budget::RsiSpendPurpose;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResearchReservationLine {
    /// Token-denominated loop work, by purpose.
    Work { purpose: RsiSpendPurpose },
    /// Exposure-denominated exploration.
    Exploration,
}
