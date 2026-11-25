//! The issuer's half of the drain guard (pass 33 row R4, 7.9): how each confirmed end and each
//! dispatch the machine never answered counts for `MACHINE_JOB_GUARD`, and the refusal a drained
//! machine gets before anything is sent or held there.
//!
//! It mirrors the node's own count (the GPU slot table's), from what the issuer observes: a lost
//! box, a refused launch, an unconfirmed release, an end inside `jobs.drain.fast_exit_secs`, and
//! a node figure above the issuer's bracket count; a run past the window resets; a caller's
//! stop, a revoke, a withdrawn key and a refusal the node wrote down for the request neither
//! count nor reset. Door 12 clears the issuer's drain, as `machines.drain.clear_by` allows, and
//! under `after_readiness_check` (the default) so does a passed readiness check that ran after
//! the drain ([`observe_node_readiness`], CG-2 row 9).
//!
//! [`observe_node_readiness`] is the issuer's reading of a node's readiness fact on its worker's
//! scheduled read of the `Node` answer (the work-order pass; a placement preview reads only): a
//! passed check clears the issuer's drain, and a run of failed checks reaches the owner as one ask
//! per run once it is long enough (pass 34, 7.3 and 16, practice 6; row Q4). The node's own drain
//! is the node's: `resume` at the box clears only that one.

use oneiron::gpu_job::MeterVerdict;
use oneiron::job_dispatch::machine_records::{MachineDrain, MachineJobOutcome};
use oneiron::machine_readiness::ReadinessEscalation;
use oneiron::{EntityId, Vault};

use crate::gpu_execution_node::wire::{
    DeviceRelease, JobEnd, JobReceipt, NodeReadiness, ReadinessState,
};

/// How the terminal receipt `ended`, billed with `meter`, counts for its machine.
#[must_use]
pub fn machine_job_outcome(
    ended: &JobReceipt,
    meter: &MeterVerdict,
    fast_exit_secs: u64,
) -> MachineJobOutcome {
    let failure = |why: String| MachineJobOutcome::MachineFailure { why };
    match &ended.end {
        Some(JobEnd::Stopped | JobEnd::Revoked | JobEnd::Withdrawn | JobEnd::Refused { .. }) => {
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

/// How far two machines' clocks may differ: `jobs.submit.skew_secs`'s default (pass 33), the bound
/// the node holds a reserve's `issued_at_ms` to. A check the node dates within it of the issuer's
/// drain may have run before the drain, so it clears nothing; the machine's next check does.
pub const READINESS_CLEAR_SKEW_MS: u64 = 120_000;

/// What the issuer did with one reading of a machine's readiness fact.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReadinessObserved {
    /// The issuer's drain a passed check cleared.
    pub cleared: Option<MachineDrain>,
    /// What a run of failed checks raised: `None` while the last check passed or before any ran.
    pub escalation: Option<ReadinessEscalation>,
}

/// The issuer's reading of `machine`'s readiness fact, from one `Node` answer it read at
/// `now_ms`, with the node's own drain in the same answer (`node_drained`):
/// - a passed check clears the issuer's drain of the machine when `machines.drain.clear_by` is
///   `after_readiness_check`, the same answer shows the node's own drain cleared, and the check
///   ran after the drain beyond [`READINESS_CLEAR_SKEW_MS`] (the check is dated by the machine's
///   clock, the drain by the issuer's; `Vault::clear_machine_job_drain_after_check`);
/// - a run of failed checks raises the owner's one ask for the run once it reaches
///   `machines.readiness.escalate_after` (`Vault::raise_machine_readiness_ask`); a later read of
///   the same run raises nothing more.
///
/// A store failure is logged and changes nothing: the machine's next check is read again.
pub fn observe_node_readiness(
    vault: &Vault,
    machine: EntityId,
    node_drained: Option<&str>,
    readiness: &NodeReadiness,
    now_ms: u64,
) -> ReadinessObserved {
    let mut observed = ReadinessObserved::default();
    if let (ReadinessState::Ready, Some(checked_at_ms), None) =
        (&readiness.state, readiness.checked_at_ms, node_drained)
    {
        let ran_after_ms = checked_at_ms.saturating_sub(READINESS_CLEAR_SKEW_MS);
        match vault.clear_machine_job_drain_after_check(machine, ran_after_ms, now_ms) {
            Ok(Some(drain)) => {
                tracing::info!(machine = %machine.to_hex(), was = %drain.why, checked_at_ms, "vault_machine: a passed readiness check cleared the issuer's drain");
                observed.cleared = Some(drain);
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(machine = %machine.to_hex(), %error, "vault_machine: the issuer's drain not cleared after a passed readiness check");
            }
        }
    }
    if let Some(streak) = readiness.streak(machine) {
        match vault.raise_machine_readiness_ask(&streak) {
            Ok(escalation) => {
                if let ReadinessEscalation::Asked {
                    seq,
                    queued_now: true,
                } = escalation
                {
                    tracing::warn!(machine = %machine.to_hex(), seq, failed_in_a_row = streak.failed_in_a_row, "vault_machine: a machine keeps failing its readiness check; the owner is asked");
                }
                observed.escalation = Some(escalation);
            }
            Err(error) => {
                tracing::warn!(machine = %machine.to_hex(), %error, "vault_machine: the readiness ask not raised");
            }
        }
    }
    observed
}
