//! Moved from `crates/oneiron/src/autoreason_campaign/research/budget.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::attempt_id::AttemptId;
pub use oneiron_verb_wire::autoreason_campaign::research::budget::ResearchReservationLine;
use oneiron_verb_wire::research_budget::RsiSettlement;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchReservation {
    pub id: EntityId,
    pub line: ResearchReservationLine,
    pub units: u64,
    /// The experiment the work is for, when it is one node's.
    pub attempt: Option<AttemptId>,
    pub settlement: Option<RsiSettlement>,
    pub reserved_at: u64,
}
