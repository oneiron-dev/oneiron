//! One admitted extraction attempt's bound step fixture for the red overlay: the verdict parity resources plus a lend switch.
//!
//! This door keeps the green public names while compiling against base `a1acefa491cd`, which has
//! no extraction-step lender method and no step loan type. The fixture wraps
//! [`ExtractionVerdictFixture`] without changing it: the same runtime, guard, decisions, model,
//! binding, deadline, clock and shared tally serve the bound step. The wrapper adds only a lend
//! switch. Attaching lends nothing, so the first step submit fails at the extraction facet
//! allow-list; that refusal is the red result. The tally readers expose the shared tally the test
//! cannot read itself, and the state probe reads the raw device-local keyspace the test cannot
//! name.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::extraction_verdict::{
    ExtractionVerdictFixture, NativePackSpent, fixture_charge_binding_count, fixture_charge_units,
    fixture_spent_observations,
};
use crate::LlmBackend;
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::DreamerAttemptBinding;
use crate::error::Result;
use crate::vault::Vault;

/// Holds one admitted extraction attempt's step fixture: the verdict parity resources plus a lend switch.
pub struct ExtractionStepFixture {
    /// Holds the pass resources both the verdict and step legs share.
    verdict: Arc<ExtractionVerdictFixture>,
    /// Lends the extraction step while true; lends nothing while false.
    lend: AtomicBool,
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
        }))
    }

    /// Stops lending the extraction step; receipts still answer without a loan.
    pub fn lend_nothing(&self) {
        self.lend.store(false, Ordering::SeqCst);
    }
}

/// Keeps the green attach signature while lending nothing: base has no extraction-step lender
/// method, so the binding returns unchanged and the first step submit fails at the facet
/// allow-list with the extraction refusal. The fixture stays borrowed so the test keeps its tally
/// handle.
pub fn attach_extraction_step_lender(
    binding: DreamerAttemptBinding,
    fixture: &Arc<ExtractionStepFixture>,
) -> DreamerAttemptBinding {
    let _ = fixture;
    binding
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
/// The probe reads the raw device-local keyspace without decoding: any live step-state row under
/// the attempt, or any terminal memo-index row under the attempt. A finished step deletes its
/// state row and keeps only its index row, so both prefixes are needed to see started and
/// terminal steps. A refusal before any step leaves neither. The read opens one read snapshot and
/// writes nothing.
///
/// # Errors
///
/// The vault's storage errors.
pub fn extraction_step_state_present(vault: &Vault, attempt: AttemptId) -> Result<bool> {
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    let mut state_prefix = crate::side_table::DREAMER_STEP_STATE.prefix.to_vec();
    state_prefix.extend_from_slice(attempt.as_bytes());
    let mut states = vault.store.vault_meta.prefix_iter(&txn, &state_prefix)?;
    if states.next().transpose()?.is_some() {
        return Ok(true);
    }
    let mut index_prefix = crate::side_table::DREAMER_STEP_INDEX.prefix.to_vec();
    index_prefix.extend_from_slice(attempt.as_bytes());
    let mut indexed = vault.store.vault_meta.prefix_iter(&txn, &index_prefix)?;
    Ok(indexed.next().transpose()?.is_some())
}
