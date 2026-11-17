//! One admitted extraction attempt's bound step fixture: the verdict parity resources plus a lend switch.
//!
//! The fixture wraps [`ExtractionVerdictFixture`] without changing it: the same runtime, guard,
//! decisions, model, binding, deadline, clock and shared tally serve the bound step. The wrapper
//! adds only a lend switch, so the no-loan test refuses without touching rows. The test injects its
//! own scripted backend and keeps its handle to read the request count and captured texts; this door
//! exposes the tally and the durable step-state presence the test cannot read itself.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};

use super::extraction_verdict::{
    ExtractionVerdictFixture, NativePackSpent, fixture_charge_binding_count, fixture_charge_units,
    fixture_spent_observations,
};
use crate::attempt_queue::AttemptId;
use crate::dreamer_consolidation::{DREAMER_EXTRACTION_ROLE, RoleBackend, RoleBackends, RoleCall};
use crate::dreamer_runner::{DreamerAttemptBinding, DreamerDecisionLender, ExtractionStepLoan};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::decision::{DecisionBandPolicy, DecisionLadder, TypedDecision};
use crate::llm::model_step::ModelStepReceipt;
use crate::memory::MemoryResult;
use crate::vault::Vault;
use crate::{LlmBackend, LlmRequest};

/// Holds one admitted extraction attempt's step fixture: the verdict parity resources plus a lend switch.
pub struct ExtractionStepFixture {
    /// Holds the pass resources both the verdict and step legs share.
    verdict: Arc<ExtractionVerdictFixture>,
    /// Lends the extraction step while true; lends nothing while false.
    lend: AtomicBool,
    /// Holds the host material this wake's admitted pre-hooks added, lent to each step.
    material: Mutex<Vec<String>>,
}

impl ExtractionStepFixture {
    /// Builds the fixture around `reasoner`: the verdict fixture's runtime, guard, decisions, model,
    /// binding, deadline, clock and shared tally, with lending switched on.
    ///
    /// # Errors
    ///
    /// As [`ExtractionVerdictFixture::new`].
    pub fn new(reasoner: Arc<dyn LlmBackend>) -> Result<Arc<Self>> {
        let verdict = ExtractionVerdictFixture::new(reasoner)?;
        Ok(Arc::new(Self {
            verdict,
            lend: AtomicBool::new(true),
            material: Mutex::new(Vec::new()),
        }))
    }

    /// Stops lending the extraction step; receipts still answer without a loan.
    pub fn lend_nothing(&self) {
        self.lend.store(false, Ordering::SeqCst);
    }

    /// Stores `material` as this wake's admitted host material, lent to each later step lend.
    pub fn set_hook_material(&self, material: Vec<String>) {
        *self.material.lock().unwrap_or_else(PoisonError::into_inner) = material;
    }
}

/// Lends the fixture's resources to extraction steps: it resolves the extraction role the native way
/// and runs the engine's callback with the fixture's borrowed resources.
struct FixtureStepLender {
    /// Owns the fixture holding the lent resources.
    fixture: Arc<ExtractionStepFixture>,
}

impl DreamerDecisionLender for FixtureStepLender {
    /// Refuses settlement lends: the fixture lends extraction steps only.
    fn lend(
        &self,
        _decide: &mut dyn FnMut(
            &DecisionLadder<'_>,
            &DecisionBandPolicy,
        ) -> crate::Result<TypedDecision>,
    ) -> crate::Result<TypedDecision> {
        Err(Error::InvalidConfig(
            "the step fixture lends extraction steps only".into(),
        ))
    }

    /// Resolves the extraction role through the native role routing and runs the engine's step with
    /// the fixture's borrowed resources, or lends nothing once lending is switched off.
    fn lend_extraction_step(
        &self,
        step: &mut dyn FnMut(ExtractionStepLoan<'_>) -> MemoryResult<ModelStepReceipt>,
    ) -> MemoryResult<Option<ModelStepReceipt>> {
        if !self.fixture.lend.load(Ordering::SeqCst) {
            return Ok(None);
        }
        let verdict = &*self.fixture.verdict;
        let resources = verdict.pass_resources();
        let (backend, model, binding) = verdict.extraction_route();
        let roles = RoleBackends::default().with(
            DREAMER_EXTRACTION_ROLE,
            RoleBackend {
                backend: Arc::clone(&backend),
                model: model.clone(),
                binding: binding.clone(),
                sourced: None,
            },
        );
        let call = RoleCall::resolve(
            &roles,
            DREAMER_EXTRACTION_ROLE,
            backend.as_ref(),
            &model,
            &binding,
            Some(&allow_extraction_step_egress),
        );
        let material = self
            .fixture
            .material
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        step(ExtractionStepLoan {
            call,
            prompt: &resources.decisions.extraction_prompt,
            material: &material,
            guard: &resources.guard,
            deadline: &resources.deadline,
            now_ms: resources.now_ms,
            charges: verdict.charges(),
            runtime: &resources.runtime,
        })
        .map(Some)
    }
}

/// Lends the fixture's extraction step resources to `binding` for its step calls.
pub fn attach_extraction_step_lender(
    binding: DreamerAttemptBinding,
    fixture: &Arc<ExtractionStepFixture>,
) -> DreamerAttemptBinding {
    binding.lend_decisions(Arc::new(FixtureStepLender {
        fixture: Arc::clone(fixture),
    }))
}

/// One native extraction slice over the cited turns: its turns with its exact transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeExtractionSlice {
    /// Holds the slice's turns in native chunk order.
    pub turns: Vec<EntityId>,
    /// Holds the slice's exact transcript, host material first when any rode along.
    pub transcript: String,
}

/// Renders the native extraction slices over `turns` of `attempt` with `material` as this wake's
/// admitted host material, in native slice order, without running any model.
///
/// The helper inside the consolidation module prepares only this attempt, carries the material on
/// its prepared wake, and calls native grouping, paging and rendering, so each transcript is the
/// exact input a native extraction call would read. A bound step over the same turns and material
/// must render the same bytes.
///
/// # Errors
///
/// An attempt the wake did not prepare, or the native slice build's own failures.
pub fn native_extraction_slice_transcripts(
    vault: &Vault,
    attempt: AttemptId,
    turns: &[EntityId],
    material: &[String],
) -> MemoryResult<Vec<NativeExtractionSlice>> {
    let slices = crate::dreamer_consolidation::extraction_step::native_slice_transcripts_for_test(
        vault, attempt, turns, material,
    )?;
    Ok(slices
        .into_iter()
        .map(|(turns, transcript)| NativeExtractionSlice { turns, transcript })
        .collect())
}

/// Returns every spent generation the step legs accounted, in order.
pub fn fixture_step_spent_observations(fixture: &ExtractionStepFixture) -> Vec<NativePackSpent> {
    fixture_spent_observations(&fixture.verdict)
}

/// Returns the units the fixture's shared tally charged.
pub fn fixture_step_charge_units(fixture: &ExtractionStepFixture) -> u64 {
    fixture_charge_units(&fixture.verdict)
}

/// Counts the terminal step bindings the fixture's shared tally holds.
pub fn fixture_step_charge_binding_count(fixture: &ExtractionStepFixture) -> usize {
    fixture_charge_binding_count(&fixture.verdict)
}

/// Tells whether `attempt` holds any durable extraction step state, started or terminal.
///
/// The bound step persists only what a native extraction call persists: its durable step state and
/// its `dreamer.step` record with the memo index rows. A refusal before the loan leaves none of them.
///
/// # Errors
///
/// The vault's storage errors.
pub fn extraction_step_state_present(vault: &Vault, attempt: AttemptId) -> Result<bool> {
    crate::llm::step_state_present_for_attempt(vault, attempt)
}

/// Lets the fixture step run on this server: every request is admitted.
fn allow_extraction_step_egress(_: &LlmRequest) -> bool {
    true
}
