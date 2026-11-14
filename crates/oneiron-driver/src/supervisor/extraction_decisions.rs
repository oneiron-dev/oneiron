//! Provides base-compatible extraction loan names while deliberately lending no read.

use std::sync::{Arc, Mutex};

use oneiron::dreamer_consolidation::{ConsolidationDecisions, RoleBackends, StepChargeTally};
use oneiron::dreamer_runner::DreamerDecisionLender;
use oneiron::dreamer_wake::WakeAttemptContext;
use oneiron::llm::decision::{DecisionBandPolicy, DecisionLadder, TypedDecision};
use oneiron::llm::{ExtractionEgressPredicate, HostInferenceBinding};
use oneiron::{BudgetGuard, Error, LlmBackend, ModelId, Result};
use tokio::runtime::Handle;

use super::dreamer_jobs::DreamerJobsExecutor;
use super::factory::ConsolidationExecutorFactory;

/// Names the head's public gate contract without granting a base loan.
pub trait ExtractionDecisionGate: Send + Sync {
    /// Reports whether the test host would admit the prepared route.
    fn admits(&self) -> Result<bool>;
}

/// Preserves the head's public pass-resource shape for the red branch.
pub struct ExtractionDecisionResources {
    /// Holds the pass's native decisions.
    pub decisions: ConsolidationDecisions,
    /// Holds the pass's prepared role backends.
    pub roles: RoleBackends,
    /// Holds the native fallback backend.
    pub backend: Arc<dyn LlmBackend>,
    /// Names the native fallback model.
    pub model: ModelId,
    /// Holds the native fallback host binding.
    pub binding: HostInferenceBinding,
    /// Holds the selected-model extraction permission predicate.
    pub extraction_egress: Option<Arc<dyn ExtractionEgressPredicate>>,
    /// Shares the pass's budget state.
    pub guard: BudgetGuard,
    /// Names the test host's gate.
    pub gate: Arc<dyn ExtractionDecisionGate>,
    /// Holds the fixture's live runtime handle.
    pub runtime: Handle,
}

/// Preserves the head's attempt-lender API but never lends an extraction read.
pub struct ExtractionAttemptLender {
    /// Retains an empty tally until the first missing-behavior assertion fails.
    charges: Mutex<StepChargeTally>,
}

impl ExtractionAttemptLender {
    /// Accepts the head's inputs without installing a base extraction loan.
    #[must_use]
    pub fn new(
        _resources: Arc<ExtractionDecisionResources>,
        _context: &WakeAttemptContext<'_>,
    ) -> Self {
        Self {
            charges: Mutex::new(StepChargeTally::new()),
        }
    }

    /// Preserves the head's borrowed charge-sink accessor.
    #[must_use]
    pub fn charges(&self) -> &Mutex<StepChargeTally> {
        &self.charges
    }
}

impl DreamerDecisionLender for ExtractionAttemptLender {
    /// Refuses settlement and inherits the base's default unavailable extraction loan.
    fn lend(
        &self,
        _decide: &mut dyn FnMut(&DecisionLadder<'_>, &DecisionBandPolicy) -> Result<TypedDecision>,
    ) -> Result<TypedDecision> {
        Err(Error::InvalidConfig(
            "the extraction lender does not lend conflict settlement decisions".into(),
        ))
    }
}

impl ConsolidationExecutorFactory {
    /// Accepts the head's factory call without installing a base extraction host.
    #[must_use]
    pub fn with_extraction_decisions(
        self,
        _gate: Arc<dyn ExtractionDecisionGate>,
        _runtime: Handle,
    ) -> Self {
        self
    }
}

impl<E> DreamerJobsExecutor<E> {
    /// Returns the unavailable lender so the identical test reaches its behavior assertion.
    #[must_use]
    pub fn extraction_lender(
        &self,
        _context: &WakeAttemptContext<'_>,
    ) -> Option<Arc<ExtractionAttemptLender>> {
        Some(Arc::new(ExtractionAttemptLender {
            charges: Mutex::new(StepChargeTally::new()),
        }))
    }
}
