//! Attempt-local step spend due to the shared wake ledger after memo replay.

use super::executor::PartitionRun;
use super::parallel::ExtractedPartition;
use super::recipe_failure::RecipeFailure;
use super::sieve_ports::SliceStep;
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::{DreamerParkCause, DreamerRunnerStore};
use crate::dreamer_wake::{
    DREAMER_HARD_CUT_PARK_REASON, DreamerAttemptExecution, WakeAttemptContext,
};
use crate::error::{Error, Result};
use crate::model_step_context::{StepEffectBinding, StepOutcome};
use crate::model_step_error::{DurableStepError, DurableStepResult};
use crate::store::model_step_submission::StepBudgetRefusal;
use oneiron_model::llm::{DreamerFailureDecision, LlmResponse, LlmUsage};

/// A checkpoint charges only steps without a durable paid receipt. An earlier
/// unbilled memo (for example, after a trap refunded its reservation) still
/// belongs in the next settlement; a paid checkpoint memo does not.
#[derive(Default)]
pub struct StepChargeTally {
    pub(super) units: u64,
    pub(super) step_bindings: Vec<StepEffectBinding>,
    /// Holds every spent generation the shared verdict execution accounted, in order.
    /// It serves test observation only: production settlement reads units and bindings
    /// alone.
    #[cfg(oneiron_test_support)]
    pub(super) spent_observations: Vec<SpentObservation>,
}

/// Describes one spent generation the shared verdict execution accounted: its request
/// hash, its usage, its durable binding when it claimed one, and whether it replayed
/// a memo. It serves test observation only.
#[cfg(oneiron_test_support)]
#[derive(Debug, Clone, PartialEq)]
pub struct SpentObservation {
    /// Holds the spent request hash.
    pub hash: [u8; 32],
    /// Holds the spent call's usage.
    pub usage: LlmUsage,
    /// Holds the durable step the spend claimed, or none for unclaimed usage.
    pub binding: Option<StepEffectBinding>,
    /// Tells whether the spend replayed a memoized response.
    pub memoized: bool,
}

impl StepChargeTally {
    pub(super) fn checkpoint(&self) -> DreamerAttemptExecution {
        self.park_for(DREAMER_HARD_CUT_PARK_REASON, DreamerParkCause::Checkpoint)
    }

    /// Parks with `reason` and settles what the attempt already spent, in a
    /// private park no later pass resumes.
    pub(super) fn park(&self, reason: &str) -> DreamerAttemptExecution {
        self.park_for(reason, DreamerParkCause::Other)
    }

    /// Parks on an engine `error` a recipe step met, with its text as the
    /// reason as before: privately when only an owner act clears it, else as
    /// a Retry a later pass resumes (OF-193a, [`RecipeFailure`]).
    pub(super) fn park_on_error(&self, error: &Error) -> DreamerAttemptExecution {
        self.park_for(
            &error.to_string(),
            RecipeFailure::of_error(error).park_cause(),
        )
    }

    /// Ends the try on a failed durable step: `Failed`, typed, with what
    /// the try already spent and its paid steps' receipts, when a spend
    /// scope refused the step for good or the provider refused it for its
    /// window (Engine 21 Nov 07:38); a park on the seat, with the same
    /// spend, when a spent model seat refused it (SEAT-PARK-MODEL-STEP-PATH);
    /// any other step error parks for `reason` with that error's cause, as
    /// [`Self::park_for`] does (BUDGET-TRAP-UNTYPED-NO-SENDER).
    pub(super) fn end_on_step_error(
        &self,
        reason: &str,
        error: &DurableStepError,
    ) -> DreamerAttemptExecution {
        if let Some(failed) = crate::dreamer_runner::dreamer_failed_on_refused_step(
            error,
            self.units,
            &self.step_bindings,
        ) {
            return failed;
        }
        if let Some((seat, reset_at_s)) = crate::dreamer_runner::dreamer_seat_refusal_of_step(error)
        {
            return self.park_on_seat(reason, seat, reset_at_s);
        }
        self.park_for(
            reason,
            crate::dreamer_runner::dreamer_park_cause_of_step(error),
        )
    }

    /// [`Self::end_on_step_error`] once the paid usage `error` carries (a
    /// spent correction's or a failed fallback's) has joined the tally, so
    /// the try's end settles it beside its receipts instead of refunding it
    /// (FIX 11554), a window refusal after a paid first reply among them:
    /// for a site whose earlier arms record no such usage.
    pub(super) fn end_on_step_error_with_spend(
        &mut self,
        reason: &str,
        error: &DurableStepError,
    ) -> DreamerAttemptExecution {
        if let DurableStepError::SpentLlm { usage, .. }
        | DurableStepError::SpentFallback { usage, .. } = error
        {
            self.record_usage(usage);
        }
        self.end_on_step_error(reason, error)
    }

    /// Parks on the spent model `seat` that refused a step, with `reason`
    /// and what the try already spent; the seat's available write resumes
    /// it (SEAT-PARK-MODEL-STEP-PATH).
    pub(super) fn park_on_seat(
        &self,
        reason: &str,
        seat: crate::dreamer_runner::ModelSeatId,
        reset_at_s: Option<u64>,
    ) -> DreamerAttemptExecution {
        DreamerAttemptExecution::ParkOnSeatWithSpend {
            reason: reason.to_owned(),
            seat: *seat.as_bytes(),
            reset_at_s,
            completed_units: self.units,
            step_bindings: self.step_bindings.clone(),
        }
    }

    /// Ends the try `Failed` for `reason` on a step a spend scope refused
    /// for good, `refusal` typed beside it, with what the try already spent
    /// and its paid steps' receipts.
    pub(super) fn fail_refused(
        &self,
        reason: &str,
        refusal: StepBudgetRefusal,
    ) -> DreamerAttemptExecution {
        DreamerAttemptExecution::Failed {
            reason: reason.to_owned(),
            completed_units: self.units,
            budget_refusal: Some(refusal),
            step_bindings: self.step_bindings.clone(),
        }
    }

    /// Ends the try `Failed` for `reason`, untyped, with what it already
    /// spent and its paid steps' receipts: a call the provider refused for
    /// its window, which the same input meets on every call, so no later
    /// pass resends it (Engine 21 Nov 07:38).
    pub(super) fn fail_for(&self, reason: &str) -> DreamerAttemptExecution {
        DreamerAttemptExecution::Failed {
            reason: reason.to_owned(),
            completed_units: self.units,
            budget_refusal: None,
            step_bindings: self.step_bindings.clone(),
        }
    }

    /// [`Self::park`] with a typed cause, for a failed model call or step.
    pub(super) fn park_for(
        &self,
        reason: &str,
        cause: DreamerParkCause,
    ) -> DreamerAttemptExecution {
        DreamerAttemptExecution::ParkWithSpend {
            reason: reason.to_owned(),
            cause,
            completed_units: self.units,
            step_bindings: self.step_bindings.clone(),
        }
    }

    /// Parks on a deterministic fallback's `response` to the step
    /// `step_hash`. A fallback that stood in for a provider outage parks as
    /// one, and the step's memo goes with it, so the attempt the offer's
    /// recovery resumes asks the model again rather than replaying the
    /// fallback (OF-305). A Retry's memo goes too (FIX 7431): a site's check
    /// refuses such a fallback inside its step, so only one stored before
    /// that check reaches here.
    ///
    /// The step's paid receipt goes with its memo, and this park pins none
    /// for it, so the call the resumed attempt asks again charges its own
    /// usage to the wake ledger's settlement (FIX 2851); the fallback's units
    /// stay in this park's spend. The receipt and the memo go in one write,
    /// so a crash leaves either both or neither (FIX 7489).
    pub(super) fn park_on_fallback(
        &self,
        vault: &Vault,
        attempt_id: AttemptId,
        step_hash: [u8; 32],
        reason: &str,
        response: &LlmResponse,
    ) -> Result<DreamerAttemptExecution> {
        let cause = crate::dreamer_runner::dreamer_park_cause_of_response(response);
        if !matches!(
            cause,
            DreamerParkCause::ProviderUnavailable | DreamerParkCause::Retry
        ) {
            return Ok(self.park_for(reason, cause));
        }
        forget_charged_step(vault, attempt_id, &step_hash)?;
        Ok(DreamerAttemptExecution::ParkWithSpend {
            reason: reason.to_owned(),
            cause,
            completed_units: self.units,
            step_bindings: self
                .step_bindings
                .iter()
                .copied()
                .filter(|binding| {
                    *binding
                        != StepEffectBinding {
                            attempt_id,
                            step_hash,
                        }
                })
                .collect(),
        })
    }

    /// Parks Retry on a memoized reply to the step `step_hash` that its site
    /// refuses for `reason` (FIX 7431, Engine 10-21): one stored before the
    /// site's check refused such replies inside the step. The memo and the
    /// charge mark go together in one write, so the next try asks the model
    /// again and its paid answer is tallied once as a fresh step (FIX 7489);
    /// this park pins none for it, while the refused call's units stay in its
    /// spend (that call was paid).
    pub(super) fn park_refused_reply(
        &self,
        vault: &Vault,
        attempt_id: AttemptId,
        step_hash: [u8; 32],
        reason: &str,
    ) -> Result<DreamerAttemptExecution> {
        forget_charged_step(vault, attempt_id, &step_hash)?;
        Ok(DreamerAttemptExecution::ParkWithSpend {
            reason: reason.to_owned(),
            cause: DreamerParkCause::Retry,
            completed_units: self.units,
            step_bindings: self
                .step_bindings
                .iter()
                .copied()
                .filter(|binding| {
                    *binding
                        != StepEffectBinding {
                            attempt_id,
                            step_hash,
                        }
                })
                .collect(),
        })
    }

    pub(super) fn record_terminal(
        &mut self,
        vault: &Vault,
        attempt_id: AttemptId,
        step_hash: [u8; 32],
        usage: &LlmUsage,
    ) -> Result<()> {
        let binding = StepEffectBinding {
            attempt_id,
            step_hash,
        };
        if self.step_bindings.contains(&binding)
            || DreamerRunnerStore::new(vault).checkpoint_step_charged(attempt_id, &step_hash)?
        {
            return Ok(());
        }
        self.step_bindings.push(binding);
        self.record_usage(usage);
        Ok(())
    }

    /// [`Self::record_terminal`] for an attempt whose run line the driver
    /// meters: a step newly tallied is noted on `ctx`'s meter too, so a later
    /// engine error or park that settles the line's charge pins its paid
    /// receipt and a replay of its memo is not paid again (FIX 6100).
    pub(super) fn record_terminal_metered(
        &mut self,
        ctx: &WakeAttemptContext<'_>,
        attempt_id: AttemptId,
        step_hash: [u8; 32],
        usage: &LlmUsage,
    ) -> Result<()> {
        let tallied = self.step_bindings.len();
        self.record_terminal(ctx.vault, attempt_id, step_hash, usage)?;
        if self.step_bindings.len() > tallied {
            ctx.note_terminal_step_charge(
                StepEffectBinding {
                    attempt_id,
                    step_hash,
                },
                usage_units(usage),
            );
        }
        Ok(())
    }

    /// Failed schema correction has paid provider usage but no terminal step
    /// claim to memoize or mark as previously charged on a later wake.
    pub(super) fn record_usage(&mut self, usage: &LlmUsage) {
        self.units = self.units.saturating_add(usage_units(usage));
    }

    /// Units a scoped agent's own generation spent on the attempt's guard
    /// (FIX 7508), charged once when its parent stops waiting on it.
    pub(super) fn record_units(&mut self, units: u64) {
        self.units = self.units.saturating_add(units);
    }

    /// Creates an empty tally, holding no units, bindings or observations.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the units tallied so far.
    pub fn units(&self) -> u64 {
        self.units
    }

    /// Returns the terminal step bindings tallied so far.
    pub fn step_bindings(&self) -> &[StepEffectBinding] {
        &self.step_bindings
    }

    /// Moves this tally's units and bindings into `units` and `bindings`, leaving it
    /// empty. Test observations stay for the parity read.
    pub fn drain_into(&mut self, units: &mut u64, bindings: &mut Vec<StepEffectBinding>) {
        *units = units.saturating_add(self.units);
        self.units = 0;
        bindings.append(&mut self.step_bindings);
    }

    /// Returns every spent generation accounted so far, in order. It serves test
    /// observation only.
    #[cfg(oneiron_test_support)]
    pub fn spent_observations(&self) -> &[SpentObservation] {
        &self.spent_observations
    }
}

/// Forgets `step_hash`'s durable charge mark and its memo in ONE write, so
/// the next try's paid answer is tallied once as a fresh step and a crash
/// leaves either both or neither (FIX 7489).
fn forget_charged_step(vault: &Vault, attempt_id: AttemptId, step_hash: &[u8; 32]) -> Result<()> {
    vault.with_write_txn_grouped(|wtxn| {
        DreamerRunnerStore::new(vault).forget_step_charge_in_txn(wtxn, attempt_id, step_hash)?;
        crate::llm::forget_step_memo_in_txn(vault, wtxn, attempt_id, step_hash)
    })
}

/// The units one call's `usage` charges.
pub(crate) fn usage_units(usage: &LlmUsage) -> u64 {
    usage.input.total.saturating_add(usage.output.total)
}

/// The text parts of a model `response`, joined, as each recipe site reads
/// its reply.
pub(super) fn reply_text(response: &LlmResponse) -> String {
    response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            oneiron_model::llm::ContentPart::Text { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

/// Whether `response` is a deterministic fallback whose park a later pass
/// resumes as a Retry (FIX 7431, Engine 10-21): one that stood in for
/// neither a provider outage nor a failure only an owner act clears. A
/// site's step check refuses it, so it is paid, never memoized, and the next
/// try asks the model again. An outage's fallback still parks as one, its
/// memo dropped (OF-305); an owner-act wait keeps its private park.
pub(super) fn retry_fallback(response: &LlmResponse) -> bool {
    matches!(
        crate::dreamer_runner::dreamer_park_cause_of_response(response),
        DreamerParkCause::Retry
    )
}

/// The text of the window refusal a deterministic fallback's `response`
/// stood in for ([`crate::dreamer_wake::fatal_refuses_window`]), if it stood
/// in for one. Its reply carries nothing the call read, and the same input
/// meets the same refusal on every call: the try ends Failed with that text,
/// once, never as an empty extraction (Engine 21 Nov 07:38).
pub(super) fn window_fallback(response: &LlmResponse) -> Option<String> {
    oneiron_model::llm::FallbackRegistry::source_of(response)
        .filter(crate::dreamer_wake::fatal_refuses_window)
        .map(|source| source.to_string())
}

/// What one slice's terminal step left, once its spend is accounted:
/// the single classification the serial finish and the window arms
/// that never reach a finish both tally by, so a paid extraction
/// settles identically whichever arm accounts it (FIX 12487 round 1).
pub(super) enum SliceFate {
    Finished {
        binding: StepEffectBinding,
        response: LlmResponse,
        failure_policy: Option<DreamerFailureDecision>,
    },
    Trapped,
    Checkpoint,
    Refused(String),
    /// A spend scope refused the slice's step for good: the try ends
    /// `Failed`, typed (BUDGET-TRAP-UNTYPED-NO-SENDER).
    BudgetRefused {
        reason: String,
        refusal: StepBudgetRefusal,
    },
    /// The provider refused the slice's step for its context window: the try
    /// ends `Failed` with `reason`, once (Engine 21 Nov 07:38).
    WindowRefused {
        reason: String,
    },
    /// A spent model seat refused the slice's step: the try parks on the
    /// seat (SEAT-PARK-MODEL-STEP-PATH).
    SeatRefused {
        reason: String,
        seat: crate::dreamer_runner::ModelSeatId,
        reset_at_s: Option<u64>,
    },
}

/// Accounts one borrowed slice outcome into `charges`, without consuming it.
///
/// The charging statements and their order match `tally_slice_outcome`
/// exactly: a finished step records its terminal binding, spent schema and
/// finalize refusals record their usage, and any other spent error records
/// its usage or the unsaved usage when it carries none. Trapped steps,
/// finalize and hard-cut checkpoints, and budget refusals spend nothing. A
/// bound generation step calls this before moving its original outcome into
/// the shared receipt converter, so native and bound charge one
/// implementation with no copies.
pub(super) fn charge_borrowed_slice_outcome(
    vault: &Vault,
    outcome: &DurableStepResult<StepOutcome>,
    unsaved_usage: Option<&LlmUsage>,
    charges: &mut StepChargeTally,
) -> Result<()> {
    match outcome {
        Ok(StepOutcome::Finished {
            binding, response, ..
        }) => {
            charges.record_terminal(
                vault,
                binding.attempt_id,
                binding.step_hash,
                &response.usage,
            )?;
        }
        Ok(StepOutcome::Trapped { .. }) => {}
        Err(DurableStepError::SpentFinalizeRefused { usage }) => {
            charges.record_usage(usage);
        }
        Err(DurableStepError::SpentSchemaValidation { usage, .. }) => {
            charges.record_usage(usage);
        }
        Err(DurableStepError::FinalizeRefused | DurableStepError::DeadlineHardCut) => {}
        // A refused step spent nothing: no usage to record.
        Err(DurableStepError::BudgetRefused(_)) => {}
        Err(error) => {
            if let DurableStepError::SpentLlm { usage, .. }
            | DurableStepError::SpentFallback { usage, .. } = error
            {
                charges.record_usage(usage);
            } else if let Some(usage) = unsaved_usage {
                charges.record_usage(usage);
            }
        }
    }
    Ok(())
}

/// Accounts one slice step's outcome into `charges` and reports its
/// fate. `record_terminal` and `record_usage` are the only charge
/// sources for a partition (it registers no metered run line), so
/// every paid outcome must pass here exactly once.
pub(super) fn tally_slice_outcome(
    vault: &Vault,
    outcome: DurableStepResult<StepOutcome>,
    unsaved_usage: Option<LlmUsage>,
    charges: &mut StepChargeTally,
) -> Result<SliceFate> {
    charge_borrowed_slice_outcome(vault, &outcome, unsaved_usage.as_ref(), charges)?;
    Ok(match outcome {
        // A fallback that stood in for a window refusal is that refusal.
        Ok(StepOutcome::Finished {
            binding,
            response,
            failure_policy,
            ..
        }) => match window_fallback(&response) {
            Some(reason) => SliceFate::WindowRefused { reason },
            None => SliceFate::Finished {
                binding,
                response,
                failure_policy,
            },
        },
        Ok(StepOutcome::Trapped { .. }) => SliceFate::Trapped,
        Err(DurableStepError::SpentFinalizeRefused { .. }) => SliceFate::Checkpoint,
        Err(DurableStepError::SpentSchemaValidation { errors, .. }) => {
            SliceFate::Refused(format!("extraction reply refused: {}", errors.join("; ")))
        }
        Err(DurableStepError::FinalizeRefused | DurableStepError::DeadlineHardCut) => {
            SliceFate::Checkpoint
        }
        Err(ref error @ DurableStepError::BudgetRefused(ref refusal)) => SliceFate::BudgetRefused {
            reason: error.to_string(),
            refusal: refusal.clone(),
        },
        Err(error) => match crate::dreamer_runner::dreamer_seat_refusal_of_step(&error) {
            Some((seat, reset_at_s)) => SliceFate::SeatRefused {
                reason: error.to_string(),
                seat,
                reset_at_s,
            },
            None if crate::dreamer_wake::step_refuses_window(&error) => SliceFate::WindowRefused {
                reason: error.to_string(),
            },
            None => SliceFate::Refused(error.to_string()),
        },
    })
}

/// Accounts an extracted prefix whose finish never tallies it (a
/// window slot stopped behind an earlier slot, whose branch would not
/// re-open, or whose extraction a changed prior set discards for a
/// fresh run): the finish loop's own classification, so the paid steps
/// settle beside their receipts instead of refunding at zero. Reports
/// the run a slice already decided, in the finish loop's order:
/// `Trapped` when any slice trapped, as that step already parked the
/// attempt under its durable trap and the caller must never extract
/// past it (FIX 12487 round 2); else `BudgetRefused`, typed, when a spend
/// scope refused a slice for good; else `WindowRefused` when the provider
/// refused a slice for its window, since a park or a rerun would resend
/// that call (Engine 21 Nov 07:38); else `SeatRefused` when a spent model
/// seat refused a slice, so the try waits on that seat instead of a Retry
/// that a later pass would resume (and ask the seat again) before the
/// seat's available write (review round 2 of #7340). Each comes before the
/// caller's own arm, a park or a checkpoint, which `None` leaves.
pub(super) fn tally_extracted_outcomes(
    vault: &Vault,
    extracted: ExtractedPartition,
    charges: &mut StepChargeTally,
) -> Result<Option<PartitionRun>> {
    let mut trapped = false;
    let mut budget_refused = None;
    let mut window_refused = None;
    let mut seat_refused = None;
    for SliceStep {
        outcome,
        unsaved_usage,
        ..
    } in extracted.steps
    {
        match tally_slice_outcome(vault, outcome, unsaved_usage, charges)? {
            SliceFate::Trapped => trapped = true,
            SliceFate::BudgetRefused { reason, refusal } => {
                budget_refused.get_or_insert((reason, refusal));
            }
            SliceFate::WindowRefused { reason } => {
                window_refused.get_or_insert(reason);
            }
            SliceFate::SeatRefused {
                reason,
                seat,
                reset_at_s,
            } => {
                seat_refused.get_or_insert((reason, seat, reset_at_s));
            }
            SliceFate::Finished { .. } | SliceFate::Checkpoint | SliceFate::Refused(_) => {}
        }
    }
    if trapped {
        return Ok(Some(PartitionRun::Trapped));
    }
    if let Some((reason, refusal)) = budget_refused {
        return Ok(Some(PartitionRun::BudgetRefused { reason, refusal }));
    }
    if let Some(reason) = window_refused {
        return Ok(Some(PartitionRun::WindowRefused { reason }));
    }
    let Some((reason, seat, reset_at_s)) = seat_refused else {
        return Ok(None);
    };
    Ok(Some(PartitionRun::SeatRefused {
        reason,
        seat,
        reset_at_s,
    }))
}
