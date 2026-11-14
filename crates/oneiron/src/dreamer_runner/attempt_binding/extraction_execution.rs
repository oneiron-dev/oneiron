//! The borrowed pass resources for one checked extraction pack read.

use std::sync::Mutex;

use super::DreamerAttemptBinding;
use crate::dreamer_consolidation::extraction_pack::{
    ExtractionReadExecution, execute_checked_read,
};
use crate::memory::{
    MEMORY_CODE_INTERNAL, MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError, MemoryResult,
};
use crate::model_step_error::DurableStepError;
use crate::verbs::{AiVerdict, AiVerdictPackEntry, AiVerdictRequest};

use crate::dreamer_consolidation::{ConsolidationDecisions, RoleCall, StepChargeTally};
use crate::dreamer_wake::WakePassDeadline;
use oneiron_model::llm::BudgetGuard;
use tokio::runtime::Handle;

/// Borrows one admitted extraction attempt's decisions, route, pass clock and spend authority.
///
/// The host retains every resource for the callback. The runtime must keep driving
/// independently while the caller joins the scoped read thread; the engine neither
/// constructs a runtime nor enters one on the invoking thread.
pub struct ExtractionDecisionLoan<'a> {
    /// Borrows the held native ladder, dial, bands and per-facet wording for this call.
    pub decisions: &'a ConsolidationDecisions,
    /// Holds the verdict role resolved through the native role routing rules.
    pub call: RoleCall<'a>,
    /// Borrows the admitted attempt's own pass guard, never a newly opened budget line.
    pub guard: &'a BudgetGuard,
    /// Borrows the admitted attempt's original wake-pass deadline and finalize window.
    pub deadline: &'a WakePassDeadline,
    /// Holds the admitted attempt's frozen Unix time in milliseconds.
    pub now_ms: u64,
    /// Borrows the attempt's shared native tally, retained across every pack invocation.
    pub charges: &'a Mutex<StepChargeTally>,
    /// Borrows the live independent runtime that drives the read on a plain scoped thread.
    pub runtime: &'a Handle,
}

/// Holds the checked owned read and receipt versions that leave the validation snapshot.
pub(super) struct CheckedExtractionCall {
    /// Holds the engine's native read rows and request scope, detached from the transaction.
    pub(super) execution: crate::dreamer_consolidation::extraction_pack::CheckedExtractionRead,
    /// Holds the native plain body hashes in this read's evidence order.
    pub(super) versions: Vec<crate::model_decision::EvidenceVersion>,
    /// Holds the checked question keys in native pack order.
    pub(super) keys: Vec<Vec<String>>,
}

impl DreamerAttemptBinding {
    /// Borrows this attempt's extraction resources and joins its native read thread.
    pub(super) fn execute_extraction_pack(
        &self,
        input: &AiVerdictRequest,
        checked: &CheckedExtractionCall,
    ) -> MemoryResult<AiVerdict> {
        let lender = self
            .lender
            .as_ref()
            .ok_or_else(extraction_loan_unavailable)?;
        let mut decide = |loan: ExtractionDecisionLoan<'_>| {
            self.check()?;
            std::thread::scope(|scope| {
                scope
                    .spawn(|| {
                        let read = ExtractionReadExecution {
                            vault: &self.vault,
                            attempt: self.lease.attempt(),
                            run: self.run.clone(),
                            actor: self.actor(),
                            execution: &checked.execution,
                            versions: &checked.versions,
                            loan: &loan,
                            deadline_ms: input.deadline_ms,
                            ceiling: input.ceiling,
                        };
                        let decisions = loan
                            .runtime
                            .block_on(execute_checked_read(read))
                            .map_err(extraction_read_error)?
                            .ok_or_else(|| {
                                MemoryError::new(
                                    MEMORY_CODE_MODEL_UNAVAILABLE,
                                    "the native extraction read parked without an answer",
                                    &[],
                                )
                            })?;
                        if decisions.len() != checked.keys.len() || decisions.is_empty() {
                            return Err(MemoryError::new(
                                MEMORY_CODE_INTERNAL,
                                "the native extraction read returned a different question count",
                                &[],
                            ));
                        }
                        let mut pack = Vec::with_capacity(decisions.len());
                        for (key, kept) in checked.keys.iter().zip(decisions) {
                            // The answer native acts on: a role holder's once the question
                            // went up the role chain, none while that ask waits.
                            let answer = kept.answer().cloned().ok_or_else(|| {
                                MemoryError::new(
                                    MEMORY_CODE_MODEL_UNAVAILABLE,
                                    "the native extraction read waits on a role holder's answer",
                                    &[],
                                )
                            })?;
                            let p = kept.probability();
                            let decision = kept.decision;
                            pack.push(AiVerdictPackEntry {
                                key: key.clone(),
                                answer,
                                p,
                                rung: decision.receipt.time.and_then(|time| time.answered),
                                question: decision.receipt.question,
                                receipt: decision.receipt,
                            });
                        }
                        let first = pack.first().ok_or_else(|| {
                            MemoryError::new(
                                MEMORY_CODE_INTERNAL,
                                "the native extraction read returned no first question",
                                &[],
                            )
                        })?;
                        Ok(AiVerdict {
                            answer: first.answer.clone(),
                            p: first.p,
                            rung: first.rung,
                            receipt: first.receipt.clone(),
                            presence: None,
                            outcome: None,
                            screenshot: false,
                            until_ms: None,
                            evidence_cut_at_bytes: None,
                            pack: Some(pack),
                        })
                    })
                    .join()
                    .map_err(|_| {
                        MemoryError::new(
                            MEMORY_CODE_INTERNAL,
                            "the extraction read thread panicked",
                            &[],
                        )
                    })?
            })
        };
        lender
            .lend_extraction(&mut decide)?
            .ok_or_else(extraction_loan_unavailable)
    }
}

/// Preserves engine failures and reports a native read that could not answer.
fn extraction_read_error(error: DurableStepError) -> MemoryError {
    match error {
        DurableStepError::Engine(error) => error.into(),
        error => MemoryError::new(
            MEMORY_CODE_MODEL_UNAVAILABLE,
            format!("the native extraction read failed: {error}"),
            &[],
        ),
    }
}

/// Keeps the checked no-loan refusal identical for every unstaffed extraction host.
fn extraction_loan_unavailable() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_MODEL_UNAVAILABLE,
        "no extraction loan is lent to this attempt",
        &["The extraction attempt parks until its host lends an extraction read."],
    )
}
