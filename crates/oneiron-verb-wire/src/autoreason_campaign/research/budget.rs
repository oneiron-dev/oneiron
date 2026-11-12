//! Moved from `crates/oneiron/src/autoreason_campaign/research/budget.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::research_budget::RsiSpendPurpose;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchReservationLine {
    /// Token-denominated loop work, by purpose.
    Work { purpose: RsiSpendPurpose },
    /// Exposure-denominated exploration.
    Exploration,
}

/// The campaign's lease and what it has committed against it.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ResearchBudgetRead {
    pub max_units: u64,
    pub exploration_units: u64,
    pub work_reserved: u64,
    pub work_spent: u64,
    pub exploration_reserved: u64,
    pub exploration_spent: u64,
}

impl ResearchBudgetRead {
    fn work_committed(&self) -> u64 {
        self.work_reserved.saturating_add(self.work_spent)
    }

    fn exploration_committed(&self) -> u64 {
        self.exploration_reserved
            .saturating_add(self.exploration_spent)
    }
}
