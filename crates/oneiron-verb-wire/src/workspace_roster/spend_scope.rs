//! Moved from `crates/oneiron/src/workspace_roster/spend_scope.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::attempt_id::AttemptId;
use serde::Deserialize;
use serde::Serialize;

/// Whether a scope still takes spend and reservations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SpendState {
    Open,
    /// Settled into its parent. Late spend lands on the nearest open ancestor.
    Closed,
}
