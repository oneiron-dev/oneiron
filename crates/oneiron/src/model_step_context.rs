//! Caller-owned model-step context and terminal outcomes.

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::dreamer_wake::{BudgetLegibilityEnvelope, WakePassDeadline};
use crate::entity_id::EntityId;
use crate::model_step_record::TrapRef;
use crate::write_envelope::WriteActor;
use oneiron_model::llm::{DreamerFailureDecision, LlmResponse};

/// Caller-owned context for one durable step. The dispatcher owns
/// `envelope_actor`; guests never supply it.
#[derive(Clone)]
pub struct DurableStepContext<'a> {
    pub vault: &'a Vault,
    pub attempt_id: AttemptId,
    pub run_id: Option<String>,
    pub envelope_actor: WriteActor,
    pub subject: EntityId,
    /// The wake-pass deadline (ONE-1305): Some inside wake passes. Enables
    /// the finalize-window refusal for NEW steps and the budget legibility
    /// envelope on finished outcomes. Admitted calls may finish after expiry.
    pub deadline: Option<&'a WakePassDeadline>,
    pub now_ms: u64,
}

impl DurableStepContext<'_> {
    /// The step clock in Unix SECONDS. Park rows store `parked_at` in seconds
    /// (`park_attempt_with_progress` multiplies it by 1_000 for `updated_at_ms`),
    /// so the millisecond `now_ms` must be divided down before it reaches
    /// `park_attempt` — otherwise `parked_at` lands ~1000x too large (#480-1).
    pub(crate) const fn now_s(&self) -> u64 {
        self.now_ms / 1_000
    }
}

/// Terminal outcome of [`call_as_step`](crate::llm::call_as_step).
#[derive(Debug, Clone, PartialEq)]
pub enum StepOutcome {
    Finished {
        response: LlmResponse,
        memoized: bool,
        /// Budget legibility (ONE-1305): Some inside wake passes (when
        /// [`DurableStepContext::deadline`] is set), None outside.
        legibility: Option<BudgetLegibilityEnvelope>,
        /// Restrictive policy for a deterministic failure result; never an authority grant.
        failure_policy: Option<DreamerFailureDecision>,
    },
    Trapped {
        trap: TrapRef,
        /// Budget-denial policy, resolved before parking this attempt.
        failure_policy: DreamerFailureDecision,
    },
}
