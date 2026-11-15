//! Moved from `crates/oneiron/src/llm/budget/resident.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::store::resident_budget_rows::AllocationRef;
use oneiron_contracts::entity_id::EntityId;
use oneiron_verb_wire::store::resident_budget_rows::ResidentShare;
use serde::Deserialize;
use serde::Serialize;

/// One resident's share and depletion, as the owner reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidentShareRead {
    pub resident: EntityId,
    pub share: ResidentShare,
    /// The allocation the counts are on; `None` before any charge.
    pub allocation: Option<AllocationRef>,
    pub used_units: u64,
    pub overdraft_units: u64,
    pub overdrafts: u64,
}
