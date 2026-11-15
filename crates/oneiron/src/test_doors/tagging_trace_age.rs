//! Door for `tests/expiry_boundaries.rs` (UC-12 PR 4): records a tagging trace at one second
//! and runs the trace history's age prune at another, which no public door does on demand.

use crate::error::Result;
use crate::{EntityId, Vault};

/// Records one first-try trace of `turn` at `recorded_at`. A vault with no tagging armed
/// records nothing.
///
/// # Errors
///
/// Storage errors.
pub fn record_trace(vault: &Vault, turn: EntityId, recorded_at: u64) -> Result<()> {
    vault.record_tagging_trace_for_test(turn, recorded_at)
}

/// One round of the age prune at `now`; how many traces went.
///
/// # Errors
///
/// Storage errors.
pub fn prune_expired_traces(vault: &Vault, now: u64) -> Result<usize> {
    vault.prune_expired_tagging_traces_for_test(now)
}
