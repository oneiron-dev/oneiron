//! Doors for the agent-run placement tests (row P4,
//! `crates/oneiron/tests/native_run_placement.rs`): another machine's
//! capacity record as sync would bring it, and where a run was placed.

use crate::agent_dispatch::run_placement_of;
use crate::attempt_queue::AttemptId;
use crate::error::Result;
use crate::machine_capacity::MachineCapacity;
use crate::work_order::record::SlotDecision;
use crate::{EntityId, Vault};

/// Records `capacity` on `machine`'s MACHINE entity in `vault`, as that
/// machine's own probe records it and sync brings it to every machine.
///
/// # Errors
///
/// Storage errors.
pub fn record_capacity_of(
    vault: &Vault,
    machine: EntityId,
    capacity: &MachineCapacity,
) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        vault
            .record_capacity_in_txn(txn, machine, capacity)
            .map(drop)
    })
}

/// The machine the run of the try `attempt` was placed on at its first
/// claim, and the PLACE decision; `None` when it was not placed.
///
/// # Errors
///
/// A run TASK that does not read, and storage errors.
pub fn placement(vault: &Vault, attempt: AttemptId) -> Result<Option<(EntityId, SlotDecision)>> {
    Ok(run_placement_of(vault, attempt)?.map(|placement| (placement.machine, placement.decision)))
}
