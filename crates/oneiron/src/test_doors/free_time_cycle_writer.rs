//! A door to the free-time cycle writer (FABLE-6918-1): the writer of one
//! due boundary alone, as `enqueue_due_free_time_cycles` runs it after its
//! scan, so a test can stand a scan that read the policy before a later act.

use crate::{EntityId, Result, Vault};

/// Runs the writer for a `boundary` the scan found for `agent` at `now`, on
/// node `local_node_id`: `true` when a cycle opened.
///
/// # Errors
/// A store read or write that fails.
pub fn open_scanned_boundary(
    vault: &Vault,
    agent: EntityId,
    boundary: u64,
    now: u64,
    local_node_id: u64,
) -> Result<bool> {
    vault.open_scanned_free_time_boundary_for_doors(agent, boundary, now, local_node_id)
}
