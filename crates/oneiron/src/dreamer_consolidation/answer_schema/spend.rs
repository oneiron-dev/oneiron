//! What one answer-schema check's calls spent (HOUSE-SCHEMA-CHECK): the compaction check's
//! `Spend` shape, units with the terminal step bindings, on the house rung instead of its
//! ladder. Each terminal step is booked once; a park or failure carries the spend so far.

use crate::dreamer_runner::DreamerParkCause;
use crate::dreamer_wake::DreamerAttemptExecution;
use crate::error::Result;
use crate::model_step_context::StepEffectBinding;
use crate::model_step_error::DurableStepError;
use oneiron_model::llm::LlmUsage;

/// What a check's calls spent, each terminal step booked once.
#[derive(Default)]
pub(crate) struct Spend {
    pub(crate) units: u64,
    pub(crate) step_bindings: Vec<StepEffectBinding>,
}

impl Spend {
    /// Books one fresh (never memoized) answer's usage with its terminal step.
    pub(crate) fn add(&mut self, usage: &LlmUsage, binding: StepEffectBinding) {
        self.units = self
            .units
            .saturating_add(usage.input.total.saturating_add(usage.output.total));
        if !self.step_bindings.contains(&binding) {
            self.step_bindings.push(binding);
        }
    }

    /// Charges what a failed call spent before it failed: a spent LLM failure's usage.
    pub(crate) fn charge_failed(&mut self, error: &DurableStepError) {
        if let DurableStepError::SpentLlm { usage, .. } = error {
            self.units = self
                .units
                .saturating_add(usage.input.total.saturating_add(usage.output.total));
        }
    }

    /// The attempt completed, this spend settled with its terminal steps pinned as paid.
    pub(crate) fn completed(self) -> DreamerAttemptExecution {
        DreamerAttemptExecution::Completed {
            completed_units: self.units,
            step_bindings: self.step_bindings,
        }
    }

    /// The attempt parked for `reason`, this spend kept.
    fn park_with_spend(self, reason: &str, cause: DreamerParkCause) -> DreamerAttemptExecution {
        DreamerAttemptExecution::ParkWithSpend {
            reason: reason.to_owned(),
            cause,
            completed_units: self.units,
            step_bindings: self.step_bindings,
        }
    }

    /// The attempt parked for `reason`; a plain park while nothing was spent.
    fn park(self, reason: &str, cause: DreamerParkCause) -> DreamerAttemptExecution {
        if self.units == 0 && self.step_bindings.is_empty() {
            DreamerAttemptExecution::Park {
                reason: reason.to_owned(),
                cause,
            }
        } else {
            self.park_with_spend(reason, cause)
        }
    }

    /// The attempt a durable step suspended, to resume.
    pub(crate) fn trapped(self) -> DreamerAttemptExecution {
        self.park("durable step trapped for resume", DreamerParkCause::Signal)
    }

    /// How the attempt waits after a durable step failed, this spend kept; an engine error
    /// stays one.
    pub(crate) fn parked_on(mut self, error: DurableStepError) -> Result<DreamerAttemptExecution> {
        if let Some(failed) = crate::dreamer_runner::dreamer_failed_on_refused_step(
            &error,
            self.units,
            &self.step_bindings,
        ) {
            return Ok(failed);
        }
        if let Some((seat, reset_at_s)) =
            crate::dreamer_runner::dreamer_seat_refusal_of_step(&error)
        {
            return Ok(DreamerAttemptExecution::ParkOnSeatWithSpend {
                reason: error.to_string(),
                seat: *seat.as_bytes(),
                reset_at_s,
                completed_units: self.units,
                step_bindings: self.step_bindings,
            });
        }
        Ok(match error {
            DurableStepError::SpentFinalizeRefused { usage } => {
                self.units = self
                    .units
                    .saturating_add(usage.input.total.saturating_add(usage.output.total));
                self.park_with_spend(
                    crate::dreamer_wake::DREAMER_HARD_CUT_PARK_REASON,
                    DreamerParkCause::Checkpoint,
                )
            }
            DurableStepError::DeadlineHardCut => self.park(
                crate::dreamer_wake::DREAMER_HARD_CUT_PARK_REASON,
                DreamerParkCause::Checkpoint,
            ),
            DurableStepError::FinalizeRefused => {
                self.park("wake pass finalize window", DreamerParkCause::Checkpoint)
            }
            DurableStepError::Engine(error) => return Err(error),
            other => self.park(
                &other.to_string(),
                crate::dreamer_runner::dreamer_park_cause_of_step(&other),
            ),
        })
    }
}
