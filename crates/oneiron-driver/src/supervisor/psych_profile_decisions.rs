//! Lends a prepared pass's resources to one psych profile attempt's bound
//! generation step (untangle 6.9i).
//!
//! The step borrows the narrative role and the original attempt's guard,
//! clock and charge tally; the host keeps its backend, guard and runtime.

use std::sync::{Arc, Mutex};

use oneiron::dreamer_consolidation::{DREAMER_NARRATIVE_ROLE, RoleCall, StepChargeTally};
use oneiron::dreamer_runner::{DreamerDecisionLender, PsychProfileStepLoan};
use oneiron::dreamer_wake::{WakeAttemptContext, WakePassDeadline};
use oneiron::llm::decision::{DecisionBandPolicy, DecisionLadder, TypedDecision};
use oneiron::llm::model_step::ModelStepReceipt;
use oneiron::memory::MemoryResult;
use oneiron::{Error, Result};

use super::extraction_decisions::ExtractionDecisionResources;

/// Owns one psych profile attempt's clock and charge sink for its bound step.
pub struct PsychProfileAttemptLender {
    /// Retains the prepared pass resources for every borrowed callback.
    resources: Arc<ExtractionDecisionResources>,
    /// Preserves the admitted attempt's original clock and finalize window.
    deadline: WakePassDeadline,
    /// Preserves the admitted attempt's frozen Unix time in milliseconds.
    now_ms: u64,
    /// Retains all terminal generation charges until the job hands off its outcome.
    charges: Mutex<StepChargeTally>,
}

impl PsychProfileAttemptLender {
    /// Retains the admitted attempt's own context and registers its shared pass meter.
    ///
    /// The profile job must hand this lender's charge sink to the same
    /// attempt's outcome, including a paid refused reply.
    #[must_use]
    pub fn new(
        resources: Arc<ExtractionDecisionResources>,
        context: &WakeAttemptContext<'_>,
    ) -> Self {
        context.meter_run_line(&resources.guard);
        Self {
            resources,
            deadline: context.deadline.clone(),
            now_ms: context.now_ms,
            charges: Mutex::new(StepChargeTally::new()),
        }
    }

    /// Borrows the tally the bound step charges, for the outcome handoff.
    #[must_use]
    pub fn charges(&self) -> &Mutex<StepChargeTally> {
        &self.charges
    }
}

impl DreamerDecisionLender for PsychProfileAttemptLender {
    /// Refuses settlement because its existing host lender remains separate.
    fn lend(
        &self,
        _decide: &mut dyn FnMut(&DecisionLadder<'_>, &DecisionBandPolicy) -> Result<TypedDecision>,
    ) -> Result<TypedDecision> {
        Err(Error::InvalidConfig(
            "the psych profile lender does not lend conflict settlement decisions".into(),
        ))
    }

    /// Rechecks the narrative gate and lends the attempt's narrative role once.
    fn lend_psych_profile_step(
        &self,
        step: &mut dyn FnMut(PsychProfileStepLoan<'_>) -> MemoryResult<ModelStepReceipt>,
    ) -> MemoryResult<Option<ModelStepReceipt>> {
        let resources = &self.resources;
        if !resources.gate.admits_narrative_step()? {
            return Ok(None);
        }
        let call = RoleCall::resolve(
            &resources.roles,
            DREAMER_NARRATIVE_ROLE,
            resources.backend.as_ref(),
            &resources.model,
            &resources.binding,
            resources.extraction_egress.as_deref(),
        );
        step(PsychProfileStepLoan {
            call,
            guard: &resources.guard,
            deadline: &self.deadline,
            now_ms: self.now_ms,
            charges: &self.charges,
            runtime: &resources.runtime,
        })
        .map(Some)
    }
}
