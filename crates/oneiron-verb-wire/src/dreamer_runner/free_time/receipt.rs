//! Moved from `crates/oneiron/src/dreamer_runner/free_time/receipt.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// How one item ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FreeTimeItemOutcome {
    /// It did its work: a for-human item that landed its proposal, an
    /// own-time item whose reflection landed.
    Completed,
    /// Own time the agent chose to rest: no call, no spend, no text.
    Rested,
    /// It ran and landed nothing.
    Failed,
    /// It ended without doing its work: its cycle ended first, or it had
    /// nothing to run on.
    Cancelled,
}

/// Whether a cycle's floor holds, as its receipts show.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FreeTimeFloor {
    /// A for-human item landed a proposal, and an own-time item reflected
    /// or rested.
    Met,
    /// Every receipt was read, and one kind has none that meets it.
    NotMet,
    /// Not every receipt could be read: nothing is said either way.
    Unknown,
}
