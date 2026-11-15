//! Moved from `crates/oneiron/src/consent/settlement_fact.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

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
