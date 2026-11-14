//! Lends a prepared pass's native decision resources to one extraction attempt.

use std::sync::{Arc, Mutex};

use oneiron::dreamer_consolidation::{
    ConsolidationDecisions, DREAMER_VERDICT_ROLE, RoleBackends, RoleCall, StepChargeTally,
};
use oneiron::dreamer_runner::{DreamerDecisionLender, ExtractionDecisionLoan};
use oneiron::dreamer_wake::{WakeAttemptContext, WakePassDeadline};
use oneiron::llm::decision::{DecisionBandPolicy, DecisionLadder, TypedDecision};
use oneiron::llm::{ExtractionEgressPredicate, HostInferenceBinding};
use oneiron::memory::MemoryResult;
use oneiron::verbs::AiVerdict;
use oneiron::{BudgetGuard, Error, LlmBackend, ModelId, Result};
use tokio::runtime::Handle;

/// Rechecks the host's live permission before each extraction loan.
pub trait ExtractionDecisionGate: Send + Sync {
    /// Admits the prepared verdict route without selecting another model or run.
    ///
    /// # Errors
    ///
    /// Returns failures while reading the host's live admission policy.
    fn admits(&self) -> Result<bool>;
}

/// Owns the native resources shared by extraction loans within one prepared pass.
///
/// Cloned guards share the pass's spend state. The runtime must remain independently
/// driven while the engine joins its scoped read thread.
pub struct ExtractionDecisionResources {
    /// Holds the pass's ladder, dial, learned bands, checker and wording.
    pub decisions: ConsolidationDecisions,
    /// Holds the pass's prepared role backends and their existing runs.
    pub roles: RoleBackends,
    /// Holds the fallback backend used by native role resolution.
    pub backend: Arc<dyn LlmBackend>,
    /// Names the fallback model used by native role resolution.
    pub model: ModelId,
    /// Holds the fallback host attestation used by native role resolution.
    pub binding: HostInferenceBinding,
    /// Holds the pass's selected-model extraction permission predicate.
    pub extraction_egress: Option<Arc<dyn ExtractionEgressPredicate>>,
    /// Shares the admitted pass's own budget state.
    pub guard: BudgetGuard,
    /// Rechecks the prepared route's live host permission at every loan.
    pub gate: Arc<dyn ExtractionDecisionGate>,
    /// Drives the engine's read on the host's independent live runtime.
    pub runtime: Handle,
}

/// Owns one extraction attempt's clock and charge sink across its bound verdict calls.
pub struct ExtractionAttemptLender {
    /// Retains the prepared pass resources for every borrowed callback.
    resources: Arc<ExtractionDecisionResources>,
    /// Preserves the admitted attempt's original clock and finalize window.
    deadline: WakePassDeadline,
    /// Preserves the admitted attempt's frozen Unix time in milliseconds.
    now_ms: u64,
    /// Retains all terminal generation charges until the job hands off its outcome.
    charges: Mutex<StepChargeTally>,
}

impl ExtractionAttemptLender {
    /// Retains the admitted attempt's own context and registers its shared pass meter.
    ///
    /// The extraction job must retain this lender across all verdict calls and hand
    /// its charge sink to the same attempt's outcome, including paid failure prefixes.
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

    /// Borrows the attempt-owned tally for the job's outcome and failure handoff.
    #[must_use]
    pub fn charges(&self) -> &Mutex<StepChargeTally> {
        &self.charges
    }
}

impl DreamerDecisionLender for ExtractionAttemptLender {
    /// Refuses settlement because its existing host lender remains separate.
    fn lend(
        &self,
        _decide: &mut dyn FnMut(&DecisionLadder<'_>, &DecisionBandPolicy) -> Result<TypedDecision>,
    ) -> Result<TypedDecision> {
        Err(Error::InvalidConfig(
            "the extraction lender does not lend conflict settlement decisions".into(),
        ))
    }

    /// Rechecks the gate and lends the admitted attempt's native read resources once.
    fn lend_extraction(
        &self,
        decide: &mut dyn FnMut(ExtractionDecisionLoan<'_>) -> MemoryResult<AiVerdict>,
    ) -> MemoryResult<Option<AiVerdict>> {
        let resources = &self.resources;
        if !resources.gate.admits()? {
            return Ok(None);
        }
        let call = RoleCall::resolve(
            &resources.roles,
            DREAMER_VERDICT_ROLE,
            resources.backend.as_ref(),
            &resources.model,
            &resources.binding,
            resources.extraction_egress.as_deref(),
        );
        decide(ExtractionDecisionLoan {
            decisions: &resources.decisions,
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
