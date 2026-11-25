//! The issuer's half of the drain guard (pass 33 row R4, 7.9): how each confirmed end and each
//! dispatch the machine never answered counts for `MACHINE_JOB_GUARD`, and the refusal a drained
//! machine gets before anything is sent or held there.
//!
//! It mirrors the node's own count (the GPU slot table's), from what the issuer observes: a lost
//! box, a refused launch, an unconfirmed release, an end inside `jobs.drain.fast_exit_secs`, and
//! a node figure above the issuer's bracket count; a run past the window resets; a caller's
//! stop, a revoke, a withdrawn key and a refusal the node wrote down for the request neither
//! count nor reset. Only door 12 clears the issuer's drain, as `machines.drain.clear_by` allows.

use oneiron::gpu_job::MeterVerdict;
use oneiron::job_dispatch::machine_records::MachineJobOutcome;
use oneiron::{EntityId, Vault};

use crate::gpu_execution_node::wire::{DeviceRelease, JobEnd, JobReceipt};

/// How the terminal receipt `ended`, billed with `meter`, counts for its machine.
#[must_use]
pub fn machine_job_outcome(
    ended: &JobReceipt,
    meter: &MeterVerdict,
    fast_exit_secs: u64,
) -> MachineJobOutcome {
    let failure = |why: String| MachineJobOutcome::MachineFailure { why };
    match &ended.end {
        // A session slice's paid end (row W1) is no end of the machine's run.
        Some(
            JobEnd::Stopped
            | JobEnd::Revoked
            | JobEnd::Withdrawn
            | JobEnd::Refused { .. }
            | JobEnd::Continued,
        ) => {
            return MachineJobOutcome::NotTheMachines;
        }
        Some(JobEnd::Lost { reason, .. }) => return failure(format!("lost: {reason}")),
        Some(JobEnd::LaunchRefused { reason }) => {
            return failure(format!("launch_refused: {reason}"));
        }
        _ => {}
    }
    if let DeviceRelease::Unconfirmed { why } = &ended.release {
        return failure(format!("release_unconfirmed: {why}"));
    }
    if matches!(meter, MeterVerdict::Bracketed { .. }) {
        return failure("measured_above_bracket".to_owned());
    }
    match ended.measured_secs {
        Some(secs) if secs > fast_exit_secs => MachineJobOutcome::RanPastFastExit,
        _ => failure(format!("ended_within_{fast_exit_secs}_s")),
    }
}

/// Counts `outcome` for `machine` at `now_ms`. A store failure is logged: the guard is a
/// brake, and a count that did not land is counted again by the node's own guard.
pub fn count_outcome(vault: &Vault, machine: EntityId, outcome: &MachineJobOutcome, now_ms: u64) {
    match vault.count_machine_job_outcome(machine, outcome, now_ms) {
        Ok(guard) => {
            if let Some(drained) = &guard.drained
                && drained.at_ms == now_ms
            {
                tracing::warn!(machine = %machine.to_hex(), why = %drained.why, "vault_machine: the issuer drained a machine");
            }
        }
        Err(error) => {
            tracing::warn!(machine = %machine.to_hex(), %error, "vault_machine: the machine's job guard not counted");
        }
    }
}

/// The refusal a start or a dispatch on `machine` gets while the issuer has drained it, before
/// any reservation or network call: the code `machine_drained`. The drain's cause names what
/// the machine's runs ended with, so it stays in `MACHINE_JOB_GUARD` for door 12 and the
/// machine views, never in a job's reason (section 6, as #10414's review round 1 ruled for the
/// node's own refusals). A guard the store cannot read refuses too, as
/// `machine_guard_unreadable`: the brake fails closed. `None` while the machine is not drained.
#[must_use]
pub fn machine_job_guard_refusal(vault: &Vault, machine: EntityId) -> Option<String> {
    match vault.machine_job_drained(machine) {
        Ok(drained) => drained.map(|_| "machine_drained".to_owned()),
        Err(error) => {
            tracing::warn!(machine = %machine.to_hex(), %error, "vault_machine: the machine's job guard not read; the dispatch is refused");
            Some("machine_guard_unreadable".to_owned())
        }
    }
}
