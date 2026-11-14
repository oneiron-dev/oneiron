//! Bound extraction generation with borrowed pass resources and request-hash receipts.

use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tokio::runtime::Handle;

use super::DreamerAttemptBinding;
use super::extraction_execution::{extraction_loan_unavailable, join_extraction_thread};
use crate::dreamer_consolidation::extraction_step::execute_bound_step;
use crate::dreamer_consolidation::{RoleCall, StepChargeTally};
use crate::dreamer_wake::WakePassDeadline;
use crate::llm::model_step::{ModelStepReceipt, ModelStepReceiptRequest};
use crate::memory::{MemoryError, MemoryResult};
use crate::model_step_context::DurableStepContext;
use crate::verbs::TurnEvidence;
use oneiron_model::llm::BudgetGuard;

/// Names only the served TURN locators a bound extraction step may send.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractionStepRequest {
    /// Lists the pinned evidence entries in their transcript order.
    pub evidence: Vec<TurnEvidence>,
}

/// Borrows the extraction role and the original attempt's pass resources for one step.
///
/// The runtime drives independently while the caller joins the existing scoped thread.
/// Failure rules are loaded by the engine, never supplied by this loan or job input.
pub struct ExtractionStepLoan<'a> {
    /// Holds the extraction role resolved through the native role routing rules.
    pub call: RoleCall<'a>,
    /// Borrows the admitted attempt's own pass guard.
    pub guard: &'a BudgetGuard,
    /// Borrows the original wake-pass deadline and finalize window.
    pub deadline: &'a WakePassDeadline,
    /// Holds the attempt's frozen Unix time in milliseconds.
    pub now_ms: u64,
    /// Borrows the native terminal tally shared with this attempt's other calls.
    pub charges: &'a Mutex<StepChargeTally>,
    /// Borrows the independent runtime that drives the joined step thread.
    pub runtime: &'a Handle,
}

impl DreamerAttemptBinding {
    /// Checks served evidence, then borrows the extraction role for the original attempt.
    pub(super) fn extraction_step_submit(
        &self,
        input: ExtractionStepRequest,
    ) -> MemoryResult<ModelStepReceipt> {
        let (prepared, subject) = self.checked_extraction_step(&input)?;
        let lender = self
            .lender
            .as_ref()
            .ok_or_else(extraction_loan_unavailable)?;
        let mut step = |loan: ExtractionStepLoan<'_>| -> MemoryResult<ModelStepReceipt> {
            self.check()?;
            let result = join_extraction_thread(|| {
                let ctx = DurableStepContext {
                    vault: &self.vault,
                    attempt_id: self.lease.attempt(),
                    run_id: self.run.clone(),
                    envelope_actor: self.actor(),
                    subject,
                    deadline: Some(loan.deadline),
                    now_ms: loan.now_ms,
                    spend_scope: None,
                    wake_pass_bound: true,
                };
                loan.runtime
                    .block_on(execute_bound_step(&ctx, &prepared, &loan))
            })?;
            self.check()?;
            Ok(result)
        };
        lender
            .lend_extraction_step(&mut step)?
            .ok_or_else(extraction_loan_unavailable)
    }

    /// Reads this attempt's saved step without borrowing, admitting or charging a backend.
    pub(super) fn extraction_step_receipt(
        &self,
        input: ModelStepReceiptRequest,
    ) -> MemoryResult<ModelStepReceipt> {
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        self.check_in_txn(&txn)?;
        if input.live_run.is_some() {
            return Err(MemoryError::bad_request(
                "a bound extraction receipt takes no live_run",
            ));
        }
        let hash = extraction_step_hash(&input.step_key)?;
        crate::llm::request_hash_step_receipt_in_txn(&self.vault, &txn, self.lease.attempt(), &hash)
            .map_err(MemoryError::from)
    }
}

/// Decodes the request hash in its only accepted lowercase hexadecimal spelling.
fn extraction_step_hash(value: &str) -> MemoryResult<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(MemoryError::bad_request(
            "an extraction step key must be 64 lowercase hex digits",
        ));
    }
    let mut hash = [0; 32];
    for (out, pair) in hash.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let digit = |byte: u8| {
            if byte <= b'9' {
                byte - b'0'
            } else {
                byte - b'a' + 10
            }
        };
        *out = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Ok(hash)
}
