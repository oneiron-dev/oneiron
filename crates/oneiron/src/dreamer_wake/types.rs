//! Wake request and outcome vocabulary plus the executor contract.

use std::sync::PoisonError;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::{
    AttemptCancelReceiptKind, AttemptId, AttemptQueue, AttemptRecord, LandingTrigger,
};
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::error::Result;
use crate::model_step_context::StepEffectBinding;
use crate::settings::ReadDestination;
use crate::task_verb::{RunnerDoneAnswer, RunnerDoneQuestion};
use oneiron_model::llm::{BudgetGuard, WorkCancel};

use super::deadline::{WakeCancellation, WakePassDeadline};

#[cfg(feature = "sync")]
#[doc(hidden)]
pub use oneiron_wake_contract::dreamer_wake::types::WakeProgressLane;
#[doc(hidden)]
pub use oneiron_wake_contract::dreamer_wake::types::{
    DreamerAttemptExecution, LandingRequestNotice, RunWakePass, WakeAttemptMeter,
    WakeMilestoneAuthor, WakePassReport, WakePassStop, WakeTrigger,
};
#[doc(hidden)]
pub(super) use oneiron_wake_contract::dreamer_wake::types::{LandingRequest, ProgressKind};

pub use crate::memory::wake_observation::ClaimAuthoringFallback;

/// The error an executor panic leaves, from whichever containment
/// caught it (the driver's dispatch/flush catch, or a partition
/// window's per-slot catch): one constructor and one predicate, so
/// the driver can mark the executor-panic stage - and end the pass
/// without reusing the executor (FIX 7322) - no matter who caught it
/// (FIX 12487 round 2).
pub(crate) fn executor_panic_error() -> crate::Error {
    crate::Error::InvariantViolation("dreamer attempt executor panicked")
}

/// Whether `error` is the shared executor-panic error above.
pub(crate) fn is_executor_panic_error(error: &crate::Error) -> bool {
    matches!(
        error,
        crate::Error::InvariantViolation("dreamer attempt executor panicked")
    )
}

/// Per-attempt execution context handed to the executor.
pub struct WakeAttemptContext<'a> {
    pub vault: &'a Vault,
    pub deadline: &'a WakePassDeadline,
    /// The pass's cooperative cancellation (a drain's pause or a stop): a
    /// running attempt polls it at its boundaries and parks, resumable,
    /// when raised. `None` outside a driven pass: nothing is ever asked.
    pub cancel: Option<&'a WakeCancellation>,
    /// The pass's device-work cancellation (FIX 11963): an attempt admits
    /// its device work under a clone, so tripping it aborts in-flight
    /// device work with the pass. `None` admits unlinked, as before.
    pub device_cancel: Option<WorkCancel>,
    pub budget_id: &'a str,
    pub now_ms: u64,
    /// One frozen LMDB ledger revision for this entire wake, if the driver
    /// supplied it. Standalone direct executor calls own a local snapshot.
    pub prepared_wake: Option<&'a crate::dreamer_consolidation::PreparedWake>,
    /// Selected immutable branch plan. Non-consolidation jobs have None.
    pub prepared_attempt: Option<&'a crate::dreamer_consolidation::PreparedConsolidationAttempt>,
    /// The attempt's own run line, as the driver observes it outside the
    /// executor's future (SCAN C012): a failed or plainly parked attempt
    /// settles what that line charged. `None` observes nothing.
    pub spend_meter: Option<&'a WakeAttemptMeter>,
}

impl WakeAttemptContext<'_> {
    /// True once the pass asked this attempt to stop at its next boundary:
    /// the host paused or stopped it. An attempt that sees this parks
    /// through its checkpoint exit, and a later pass resumes it.
    #[must_use]
    pub fn cancel_requested(&self) -> bool {
        self.cancel.is_some_and(|cancel| cancel.is_cancelled())
    }

    /// Registers `line`, the attempt's own run line, at what it has already
    /// used, so the driver settles what it charges if the attempt fails or
    /// parks before reporting its spend (SCAN C012). A second line, or a
    /// context with no meter, registers nothing.
    pub fn meter_run_line(&self, line: &BudgetGuard) {
        if let Some(meter) = self.spend_meter {
            let _ = meter.line.set((line.clone(), line.read().used_units));
        }
    }

    /// Notes a terminal step newly paid on the registered run line, with its
    /// `units`, so a failure or park that settles the line's charge pins
    /// that step's paid receipt in the same settlement and a replay of its
    /// memo is not paid again (FIX 6100). With no line registered, or no
    /// meter, nothing is noted: nothing would settle its charge.
    pub fn note_terminal_step_charge(&self, binding: StepEffectBinding, units: u64) {
        if let Some(meter) = self.spend_meter
            && meter.line.get().is_some()
        {
            meter
                .terminal_steps
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((binding, units));
        }
    }

    /// Hands the driver what the executor's own tally spent before an error
    /// leaves the attempt (FIX 7432): `units`, and the terminal `step_bindings`
    /// they pay for. The error itself goes on unchanged; the failure or park
    /// that settles it charges these units and pins their receipts. With no
    /// meter nothing is handed.
    pub(crate) fn note_spend_before_error(&self, units: u64, step_bindings: &[StepEffectBinding]) {
        if let Some(meter) = self.spend_meter {
            let mut spent = meter.lock_spent_before_error();
            spent.0 = spent.0.saturating_add(units);
            for binding in step_bindings {
                if !spent.1.contains(binding) {
                    spent.1.push(*binding);
                }
            }
        }
    }

    /// The oldest stop this attempt has been asked for and not yet answered,
    /// with the trigger that motivated it — or `None` when nobody has asked.
    ///
    /// This is the worker-facing half of ONE-1896's soft rung: a request that
    /// arrives mid-execution lands on the durable row, not in the snapshot the
    /// executor was handed, so a cooperative worker POLLS here at its own
    /// step boundaries and answers by returning
    /// [`DreamerAttemptExecution::Landed`] (or by refusing through
    /// `AttemptQueue::reject_cancel`, which keeps it running and records why).
    pub fn landing_request(&self, attempt_id: AttemptId) -> Result<Option<LandingRequestNotice>> {
        let Some(record) = AttemptQueue::new(self.vault).get(attempt_id)? else {
            return Ok(None);
        };
        Ok(landing_request_notice(&record))
    }
}

/// Projects the oldest unanswered soft request off a durable row.
fn landing_request_notice(record: &AttemptRecord) -> Option<LandingRequestNotice> {
    if record.cancel_pressure().pending == 0 {
        return None;
    }
    let answered: std::collections::HashSet<u64> = record
        .cancel_receipts()
        .iter()
        .filter(|receipt| receipt.kind.answers_request())
        .filter_map(|receipt| receipt.request_sequence)
        .collect();
    record
        .cancel_receipts()
        .iter()
        .find(|receipt| {
            receipt.kind == AttemptCancelReceiptKind::SoftRequested
                && !answered.contains(&receipt.sequence)
        })
        .map(|receipt| LandingRequestNotice {
            request_sequence: receipt.sequence,
            trigger: receipt.trigger.unwrap_or(LandingTrigger::CancelRequest),
            requested_by: receipt.actor.clone(),
            reserve_units: record.landing_reserve().remaining_units(),
        })
}

/// Executes one admitted Dreamer attempt.
///
/// AT-LEAST-ONCE contract: the driver may re-execute an attempt after a crash or
/// resume — executors MUST be step-based (ONE-1343 `call_as_step`) so
/// re-execution fast-forwards through memoized steps instead of re-spending.
/// Milestones mark durable progress; this ticket does not implement step
/// memoization itself.
///
/// PARK-OWNER contract (design D2): the STEP LAYER is the one park-owner for
/// trap suspensions — it writes the trap record and parks the attempt in its own
/// wtxn. The executor still returns `Park` carrying the trap note; the
/// driver detects the existing parked row and only publishes progress,
/// never parking a second time.
#[allow(async_fn_in_trait)]
pub trait DreamerAttemptExecutor {
    async fn execute(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution>;

    /// Runs one window of plain Micro or Meso consolidation partitions the driver
    /// admitted back to back (FIX 12487): their extractions may overlap,
    /// but outcomes come back in window order and every partition commit
    /// lands serially in that order, so the committed rows equal serial
    /// `execute` calls over the same attempts. The window holds only
    /// plain partition attempts (a Micro or Meso kind, the scope's own attempt
    /// type, a Ready prepared plan, no thing branch) and sieve rung jobs
    /// the wake's preparation holds, which run whole side by side (each
    /// commits only its own span's reading); a wrapper that intercepts
    /// other shapes never sees its own shape here and may forward the
    /// window whole. The default runs the window serially.
    async fn execute_partition_window<'w>(
        &mut self,
        window: &mut [(&'w DreamerAdmittedAttempt, WakeAttemptContext<'w>)],
    ) -> Vec<Result<DreamerAttemptExecution>> {
        let mut outcomes = Vec::with_capacity(window.len());
        for (attempt, ctx) in window.iter_mut() {
            outcomes.push(self.execute(*attempt, ctx).await);
        }
        outcomes
    }

    /// The host's answer to a completed TASK try's "Done means met?"
    /// (OF-533), asked once the try's result is attached and outside any
    /// transaction. `None` judges nothing, so a briefed TASK's Done asks up.
    async fn judge_done(&self, _question: RunnerDoneQuestion) -> Option<RunnerDoneAnswer> {
        None
    }

    /// The runner ledger line a candidate's admission and settlement debit
    /// when the host routes it off the pass's line: a resident dreaming on
    /// its own model debits its own line (FIX 1152). Accounting only: `None`
    /// keeps the pass's line, and no answer refuses admission.
    fn runner_budget_id(&mut self, _candidate: &AttemptRecord) -> Option<String> {
        None
    }

    /// Whether this executor runs turn programs (DOOR-141 PR2): the driver
    /// admits program attempts only to one that does, so a pass whose host
    /// binds no program runtime admits none and changes nothing else.
    fn runs_turn_programs(&self) -> bool {
        false
    }

    /// Whether this executor runs host-model Coach jobs (`coach.host`).
    /// Opt in only when `execute` handles that queue's jobs; otherwise the
    /// pass leaves them to the host's separate Coach consumer.
    fn runs_coach_host_jobs(&self) -> bool {
        false
    }

    /// Whether this executor runs Coach heals (`coach.heal`). Independent
    /// of host-job support: `execute` must handle heals before opting in.
    fn runs_coach_heals(&self) -> bool {
        false
    }

    /// Where every model call this vended executor makes sends its input,
    /// every fallback included (FIX 12735): each of its legs holds its
    /// sends inside it and fails closed rather than go past it, so the pass
    /// lists its sources for it. `None`, the default, states no bound, and
    /// the pass lists for a destination nobody proved.
    fn destination_bound(&self) -> Option<ReadDestination> {
        None
    }
}
