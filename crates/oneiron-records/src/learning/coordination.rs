//! Moved from `crates/oneiron/src/learning/coordination.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// One peer output's reuse delay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReuseDelay {
    pub reference: String,
    pub publisher: String,
    pub user: String,
    pub published_at: u64,
    pub first_used_at: u64,
    pub delay: u64,
}

/// Work two agents did twice: a `dup_of` label saying `second` repeated
/// `first`. It cites receipts and never changes the closed work it names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuplicateWork {
    pub first: String,
    /// The work that repeated `first`.
    pub second: String,
    pub kind: DuplicateWorkKind,
    pub labelled_by: DuplicateLabeller,
    /// What the label cites: the audit's receipt, or the health recipe's
    /// diagnostic.
    pub receipt: String,
}

/// What a repeat was (ARCH-0079 #coordination-cost): only a redundant one
/// is waste.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DuplicateWorkKind {
    /// Unplanned work on the same input.
    Redundant,
    /// Overlap the team's pattern plans, such as a committee's second look.
    PlannedCheck,
    /// Not enough context to tell.
    Unknown,
}

/// Who wrote a duplicate-work label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DuplicateLabeller {
    Audit,
    /// The agent-health recipe's digest pairs.
    Health,
}

/// A team's coordination cost, shown beside elapsed time and calls.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinationCost {
    pub team_ref: String,
    /// Agent-seconds spent waiting, by reason.
    pub wait_by_reason: BTreeMap<String, u64>,
    pub reuse_delays: Vec<ReuseDelay>,
    pub duplicate_work: Vec<DuplicateWork>,
    /// First event to last event, in seconds.
    pub elapsed: u64,
    /// Attempts the team made.
    pub calls: u64,
    pub derived_at: u64,
}
