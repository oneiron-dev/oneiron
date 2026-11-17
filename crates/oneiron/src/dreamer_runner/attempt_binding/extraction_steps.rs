//! Bound extraction generation with borrowed pass resources and request-hash receipts.

use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tokio::runtime::Handle;

use super::DreamerAttemptBinding;
use super::extraction_execution::{extraction_loan_unavailable, join_extraction_thread};
use crate::dreamer_consolidation::extraction_step::execute_bound_step;
use crate::dreamer_consolidation::{ExtractionPrompt, RoleCall, StepChargeTally};
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
    /// Names the zero-based listing page the step shows when its slice pages.
    ///
    /// Absent means the only page. A slice whose listing pages refuses
    /// without a valid page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<usize>,
}

/// Borrows the extraction role and the original attempt's pass resources for one step.
///
/// The runtime drives independently while the caller joins the existing scoped thread.
/// Failure rules are loaded by the engine, never supplied by this loan or job input.
pub struct ExtractionStepLoan<'a> {
    /// Holds the extraction role resolved through the native role routing rules.
    pub call: RoleCall<'a>,
    /// Borrows the host's extraction prompt, the words the native pass asks in.
    pub prompt: &'a ExtractionPrompt,
    /// Holds the material this wake's admitted `host.wake` pre-hooks
    /// added, FIX 10665, which native's slices lead with.
    pub material: &'a [String],
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
    ///
    /// This door has no served pieces, so it keeps the terminal record's JSON rather
    /// than decoding the bound extraction reply as submit and resubmit do. It answers only
    /// while every queued TURN still serves and every row the step's request was read
    /// from still reads for this actor at the version the request named; otherwise every
    /// hash answers as an unknown hash does.
    pub(super) fn extraction_step_receipt(
        &self,
        input: ModelStepReceiptRequest,
    ) -> MemoryResult<ModelStepReceipt> {
        let vault = &*self.vault;
        let memory = vault.memory(self.stamp.actor, self.actor().actor_class());
        let read = memory.read_lane(crate::claim::ClaimReadStatus::Recorded)?;
        let _pins = read.prepare_point_read::<MemoryError>()?;
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        self.check_in_txn(&txn)?;
        if input.live_run.is_some() {
            return Err(MemoryError::bad_request(
                "a bound extraction receipt takes no live_run",
            ));
        }
        let hash = extraction_step_hash(&input.step_key)?;
        memory.prove_read_authority_in_txn(&txn)?;
        let reader_scope =
            crate::snapshot_read::extraction_reader_scope_in_txn(&memory, &txn, None)?;
        let receipt = read.read_projected_in_txn(&txn, &[], None, |txn, _| {
            if !self.serves_every_queued_turn_in_txn(txn, &read, reader_scope.as_ref())? {
                return Err(MemoryError::from(crate::Error::EntityNotFound));
            }
            let still_reads =
                |version: &crate::snapshot_read::SourceVersion| -> crate::Result<bool> {
                    Ok(crate::snapshot_read::observed_claim_reads_in_txn(
                        vault,
                        txn,
                        &read,
                        reader_scope.as_ref(),
                        version.entity,
                    )? && version.recheck_in_txn(&read, txn)?
                        == crate::snapshot_read::SourceVersionCheck::Current)
                };
            crate::llm::request_hash_step_receipt_in_txn(
                vault,
                txn,
                self.lease.attempt(),
                &hash,
                still_reads,
            )
            .map_err(MemoryError::from)
        })?;
        Ok(receipt.value)
    }

    /// Whether this actor's live read still serves every TURN the attempt queued.
    ///
    /// A saved reply quotes the attempt's TURNs. So a receipt answers only while the inputs
    /// page would still serve every queued TURN; once one is withheld, every hash answers as
    /// an unknown hash does. The rows a step was read from are checked beside this, by the
    /// versions its record names.
    fn serves_every_queued_turn_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        read: &crate::claim::ScopedRead<'_>,
        reader_scope: Option<&crate::federation::Scope>,
    ) -> MemoryResult<bool> {
        let vault = &*self.vault;
        let (scope, branch) =
            crate::snapshot_read::queued_extraction_branch_in_txn(vault, txn, self.attempt())?;
        for part in &branch.parts {
            let key = branch.part_key(part.conversation_ref);
            for turn in &part.turns {
                let served = crate::snapshot_read::extraction_turn_in_txn(
                    vault,
                    txn,
                    read,
                    reader_scope,
                    scope,
                    &key,
                    *turn,
                )?;
                if served.is_none() {
                    return Ok(false);
                }
            }
        }
        Ok(true)
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
