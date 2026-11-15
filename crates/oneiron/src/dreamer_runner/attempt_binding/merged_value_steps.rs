//! Bound merged-value generation with borrowed pass resources and request-hash receipts.
//!
//! The second kind of bound generation step under `ai.steps.submit`: the job
//! sends only the decided resolution with the conflict set's references, and
//! the engine rebuilds the set, renders native's resolved-value request for
//! it, and runs it on the lent verdict role. Receipts read back by the same
//! request-hash key as the extraction step, through the same receipt door.

use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tokio::runtime::Handle;

use super::DreamerAttemptBinding;
use super::extraction_execution::{extraction_loan_unavailable, join_extraction_thread};
use crate::EntityId;
use crate::claim::ClaimReadStatus;
use crate::dreamer_consolidation::extraction_pack::{
    ExtractionRebuildContext, check_engine_claim_pins, check_extraction_operands_in_txn,
    check_pack_candidates, select_routed_conflict,
};
use crate::dreamer_consolidation::merged_value_step::{
    PreparedMergedValueStep, execute_merged_value_step,
};
use crate::dreamer_consolidation::{RoleCall, StepChargeTally};
use crate::dreamer_wake::WakePassDeadline;
use crate::llm::model_step::ModelStepReceipt;
use crate::memory::{MEMORY_CODE_INTERNAL, MemoryError, MemoryResult};
use crate::model_decision::MAX_DECISION_STATE_BYTES;
use crate::model_step_context::DurableStepContext;
use crate::snapshot_read::{extraction_reader_scope_in_txn, extraction_turn_read};
use crate::verbs::{CandidateOperand, PinnedClaim};
use oneiron_model::llm::BudgetGuard;

/// The decided resolution a bound merged-value step renders: how the set resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MergedValueResolution {
    /// The members merge into one claim.
    Merge,
    /// The newest member supersedes the set's prior head.
    Supersede,
}

impl MergedValueResolution {
    /// The resolution word native's request renders.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Merge => "merge",
            Self::Supersede => "supersede",
        }
    }
}

/// Names only the decided resolution with the conflict set's references a bound merged-value step may send.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergedValueStepRequest {
    /// Holds the decided resolution the step renders: merge or supersede.
    pub resolution: MergedValueResolution,
    /// Names the zero-based index into `candidates` of the member the decision kept.
    ///
    /// Absent when the decision named none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kept: Option<usize>,
    /// Holds the candidate operands the set proposes, in order.
    pub candidates: Vec<CandidateOperand>,
    /// Holds the prior heads the engine rebuilds, in native order.
    #[serde(default)]
    pub priors: Vec<PinnedClaim>,
    /// Names the candidate indexes this step resolves, in order, when the candidates span sets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_members: Option<Vec<usize>>,
}

/// Borrows the verdict role and the original attempt's pass resources for one merged-value step.
///
/// The runtime drives independently while the caller joins the existing scoped thread.
/// Failure rules are loaded by the engine, never supplied by this loan or job input.
pub struct MergedValueStepLoan<'a> {
    /// Holds the verdict role resolved through the native role routing rules.
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
    /// Checks the conflict set references, then borrows the verdict role for the original attempt.
    pub(super) fn merged_value_step_submit(
        &self,
        input: MergedValueStepRequest,
    ) -> MemoryResult<ModelStepReceipt> {
        check_merged_value_step_bounds(&input)?;
        let (prepared, subject) = self.checked_merged_value_step(&input)?;
        let lender = self
            .lender
            .as_ref()
            .ok_or_else(extraction_loan_unavailable)?;
        let mut step = |loan: MergedValueStepLoan<'_>| -> MemoryResult<ModelStepReceipt> {
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
                    .block_on(execute_merged_value_step(&ctx, &prepared, &loan))
            })?;
            self.check()?;
            Ok(result)
        };
        lender
            .lend_merged_value_step(&mut step)?
            .ok_or_else(extraction_loan_unavailable)
    }

    /// Checks every reference and rebuilds the conflict set before borrowing a backend.
    fn checked_merged_value_step(
        &self,
        input: &MergedValueStepRequest,
    ) -> MemoryResult<(PreparedMergedValueStep, EntityId)> {
        let vault = &*self.vault;
        let memory = vault.memory(self.stamp.actor, self.actor().actor_class());
        let read = memory.read_lane(ClaimReadStatus::Recorded)?;
        let turn_read = extraction_turn_read(&read, None)?;
        let _pins = read.prepare_point_read::<MemoryError>()?;
        let _turn_pins = turn_read
            .as_ref()
            .map(crate::claim::ScopedRead::prepare_point_read::<MemoryError>)
            .transpose()?;
        let turn_read = turn_read.as_ref().unwrap_or(&read);
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        self.check_in_txn(&txn)?;
        memory.prove_read_authority_in_txn(&txn)?;
        let reader_scope = extraction_reader_scope_in_txn(&memory, &txn, None)?;
        let checked = read.read_projected_in_txn(&txn, &[], None, |txn, _| {
            let (branch, bound) = check_extraction_operands_in_txn(
                &memory,
                &read,
                txn,
                reader_scope.as_ref(),
                self.lease.attempt(),
                &input.candidates,
                Some((&[], &input.priors)),
            )?;
            let checked =
                check_pack_candidates(&input.candidates, &bound, self.lease.attempt(), &branch)?;
            let context = ExtractionRebuildContext {
                memory: &memory,
                read: &read,
                turn_read,
                txn,
                operands: &input.candidates,
            };
            let selected = select_routed_conflict(
                &checked.rows,
                &bound,
                &context,
                input.set_members.as_deref(),
            )?;
            check_engine_claim_pins(&read, txn, &input.priors, &selected.set.prior_heads)?;
            let kept = match input.kept {
                None => None,
                Some(kept) => {
                    if !selected.set.candidate_indexes.contains(&kept) {
                        return Err(MemoryError::bad_request(
                            "the merged-value kept index names no member of its conflict set",
                        ));
                    }
                    let proposal = selected.proposals.get(kept).ok_or_else(|| {
                        MemoryError::new(
                            MEMORY_CODE_INTERNAL,
                            "the merged-value conflict set names an unknown member",
                            &[],
                        )
                    })?;
                    Some(proposal.claim_id)
                }
            };
            let mut members = Vec::with_capacity(selected.set.candidate_indexes.len());
            for index in &selected.set.candidate_indexes {
                let proposal = selected.proposals.get(*index).ok_or_else(|| {
                    MemoryError::new(
                        MEMORY_CODE_INTERNAL,
                        "the merged-value conflict set names an unknown member",
                        &[],
                    )
                })?;
                members.push(proposal.clone());
            }
            let mut priors = Vec::with_capacity(selected.set.prior_heads.len());
            for id in &selected.set.prior_heads {
                let head = bound.prior(*id).ok_or_else(|| {
                    MemoryError::new(
                        MEMORY_CODE_INTERNAL,
                        "the merged-value conflict set names an unknown prior head",
                        &[],
                    )
                })?;
                priors.push(head.clone());
            }
            let subject = selected.set.identity.subject;
            Ok((
                PreparedMergedValueStep {
                    resolution: input.resolution,
                    kept,
                    members,
                    priors,
                    identity: selected.set.identity.clone(),
                    scope: bound.scope().clone(),
                },
                subject,
            ))
        })?;
        Ok(checked.value)
    }
}

/// Bounds each unbounded collection by the native decision state bound, as the verdict pack does.
fn check_merged_value_step_bounds(input: &MergedValueStepRequest) -> MemoryResult<()> {
    let lengths = [
        input.candidates.len(),
        input.priors.len(),
        input.set_members.as_ref().map_or(0, Vec::len),
    ];
    if lengths
        .iter()
        .any(|length| *length > MAX_DECISION_STATE_BYTES)
        || input
            .candidates
            .iter()
            .any(|candidate| candidate.evidence.len() > MAX_DECISION_STATE_BYTES)
    {
        return Err(MemoryError::bad_request(
            "a merged-value step collection exceeds the native decision state bound",
        ));
    }
    Ok(())
}
