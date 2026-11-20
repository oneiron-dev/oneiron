//! Proposal settlement kinds, outcomes and producer-stamped facts.

use crate::entity_id::EntityId;

#[doc(hidden)]
pub use oneiron_records::consent::settlement_fact::{SettledOutcome, SettlementKind};

/// One settlement, as its door records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettledFact {
    pub proposal: EntityId,
    pub outcome: SettledOutcome,
    pub settled_by: EntityId,
    pub kind: SettlementKind,
}
