//! The Dreamer executor's runner work (FIX 9238): each admitted attempt's
//! step is bound to its runner seat through the engine's work binding
//! ([`ByoaDispatcher::bind_runner_work_in_txn`]), so a spend that parks it
//! leaves a bound work a resume can hand on, and its terminal exhaust is
//! routed on the seat the work stands on, not the seat the executor
//! started from.

use oneiron::attempt_queue::AttemptId;
use oneiron::checkout::CheckoutId;
use oneiron::dispatch_byoa::{
    BindRunnerWork, ByoEndpointBackendFactory, ByoaDispatcher, ByoaEgressPort, ByoaError,
    ProviderAdapterRegistry, RunnerSeatChoice, RunnerSeatPolicy, RunnerWorkBindingId,
    RunnerWorkBound, RunnerWorkOutcome, runner_work_outcome, skipped_seats_note,
};
use oneiron::{DreamerAttemptExecution, DreamerParkCause, Vault};

use super::attempt_hex;

/// The step key a Dreamer attempt's runner work is bound under: one step
/// per attempt, so a second bind of the same attempt finds the first.
const DREAMER_RUNNER_STEP: &str = "byoa.runner.dreamer";

/// The Dreamer attempt `parent`'s one step: `task` on the policy's `seat`
/// as the owner ordered it, spent or not, against `checkout_id`, at `now`
/// (vault seconds).
pub(super) fn dreamer_step(
    parent: AttemptId,
    seat: usize,
    task: String,
    checkout_id: CheckoutId,
    now: u64,
) -> BindRunnerWork {
    BindRunnerWork {
        parent_attempt_id: parent,
        step_key: DREAMER_RUNNER_STEP.to_owned(),
        task,
        staged_input: None,
        checkout_id,
        task_ref: None,
        run_id: None,
        choice: RunnerSeatChoice::Seat(seat),
        now,
    }
}

/// Binds `step` and dispatches its first attempt in one writer on `vault`,
/// the dispatcher's own, and parks the Dreamer attempt for its exhaust. A
/// step bound already is answered where its work stands, with no second
/// dispatch.
pub(super) fn bind_step<B, E>(
    vault: &Vault,
    dispatcher: &ByoaDispatcher<'_, B, E>,
    registry: &ProviderAdapterRegistry,
    policy: &RunnerSeatPolicy,
    step: BindRunnerWork,
) -> oneiron::Result<DreamerAttemptExecution>
where
    B: ByoEndpointBackendFactory,
    E: ByoaEgressPort,
{
    let bound = vault.try_with_write_txn_grouped(|wtxn| {
        dispatcher.bind_runner_work_in_txn(wtxn, registry, policy, step)
    });
    let park = |reason: String, cause| Ok(DreamerAttemptExecution::Park { reason, cause });
    match bound {
        Ok(RunnerWorkBound::Bound { seat, attempt, .. }) => park(
            format!(
                "runner seat {seat} attempt {} dispatched; awaiting foreign exhaust",
                attempt_hex(attempt.as_bytes())
            ),
            DreamerParkCause::Signal,
        ),
        Ok(RunnerWorkBound::NoSeat { skipped }) => park(
            format!(
                "runner seat refused: this runtime may not run it{}",
                skipped_seats_note(&skipped)
            ),
            DreamerParkCause::Other,
        ),
        Ok(RunnerWorkBound::Exhausted { skipped, .. }) => park(
            format!(
                "runner seat spent; work parked{}",
                skipped_seats_note(&skipped)
            ),
            DreamerParkCause::Signal,
        ),
        Ok(_) => park(
            "runner seat binding is not understood by this host".to_owned(),
            DreamerParkCause::Other,
        ),
        Err(ByoaError::Store(error)) => Err(error),
        Err(other) => park(
            format!("runner seat refused: {other}"),
            DreamerParkCause::Other,
        ),
    }
}

/// The seat the Dreamer attempt `parent`'s bound work stands on now, its
/// head attempt's; `fallback`, the executor's own, for an attempt whose
/// work is not bound here or does not read.
pub(super) fn bound_seat(vault: &Vault, parent: AttemptId, fallback: usize) -> usize {
    let Ok(binding) = RunnerWorkBindingId::of(parent, DREAMER_RUNNER_STEP) else {
        return fallback;
    };
    match runner_work_outcome(vault, binding) {
        Ok(RunnerWorkOutcome::Pending { seat, .. }) => seat,
        Ok(RunnerWorkOutcome::Terminal(terminal)) => terminal.seat,
        _ => fallback,
    }
}
