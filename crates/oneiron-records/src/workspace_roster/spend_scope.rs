//! Moved from `crates/oneiron/src/workspace_roster/spend_scope.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::workspace_roster::spend_scope::SpendState;
use serde::Deserialize;
use serde::Serialize;

/// What a child launch asks of its parent's scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChildSpend {
    /// The spawn set `budget`: a hard cap the child can never pass.
    Carve { cap_units: u64 },
    /// No `budget`: hold the calibrated expected spend; top up later, up to the
    /// nearest hard ancestor's cap. A hold is never refused for its estimate.
    Hold { expected_units: u64 },
}
