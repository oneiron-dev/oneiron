//! Proposal settlement kinds, outcomes and producer-stamped facts.

use crate::entity_id::EntityId;
use serde::{Deserialize, Serialize};

/// How a proposal settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettledOutcome {
    /// A bundle approved, or a critical confirm cleared.
    Approved,
    /// A bundle declined.
    Declined,
    /// A critical confirm retracted the write.
    Retracted,
    /// A critical confirm demoted the write to a proposal.
    Demoted,
}

/// Which settlement door settled a proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementKind {
    GateConsentBundle,
    CriticalWriteConfirm,
    /// One proposed claim settled by its id (`vault.claims.settle`).
    ClaimSettlement,
}

/// One settlement, as its door records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettledFact {
    pub proposal: EntityId,
    pub outcome: SettledOutcome,
    pub settled_by: EntityId,
    pub kind: SettlementKind,
}
