//! Receipts from the existing saved-query evaluator, including actual generated usage.

use serde::{Deserialize, Serialize};

use crate::llm::LlmUsage;
use crate::llm::decision::ProviderPin;
use crate::{Error, Result};

use super::evaluator::{EvaluationRequest, SavedQueryEvaluator, WakeVisit};
use super::evidence::{EvaluationOutcome, VerdictMemoRow};
use super::storage::{MEMOS, load_record_in_txn, saved_query_type_byte};

/// One completed generation, identified by the exact request it measured.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SavedQueryGenerationReceipt {
    /// BLAKE3 of the generation request.
    pub request_hash: String,
    /// Provider-reported usage, including the host's served-provider stamp.
    pub usage: LlmUsage,
}

/// A newly measured membership judgment. A memo hit carries none.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SavedQueryJudgeReceipt {
    /// The providers the decision ladder actually reached, with model revisions.
    pub providers: Vec<ProviderPin>,
    /// Provider-reported cost per thousand at the answered rung, when known.
    /// This is not an estimate of the whole call's cost.
    pub cost_per_thousand: Option<f64>,
    /// Requests generated on the query's backend, including the separate why.
    /// Stronger synchronous ladder rungs are named by `providers`, not invented
    /// as generation usage rows here.
    pub generations: Vec<SavedQueryGenerationReceipt>,
}

/// One evaluator visit, without reconstructing a memo after an authority refusal.
#[derive(Debug, Clone, PartialEq)]
pub struct SavedQueryEvaluation {
    /// The existing staged evaluator's answer.
    pub outcome: EvaluationOutcome,
    /// What this visit cost the query's bounds.
    pub visit: WakeVisit,
    /// The exact memo read or written by this evaluation; never one for a refusal.
    pub memo: Option<VerdictMemoRow>,
    /// New judge measurements; none for a hard match or memo hit.
    pub judge: Option<SavedQueryJudgeReceipt>,
}

/// The evaluator's memo write, under a current definition and current owner read.
/// A provider await may not carry a superseded definition or a revoked read
/// into a later write. The memo still pins the evidence actually judged.
pub(super) fn put_evaluated_memo(
    evaluator: &SavedQueryEvaluator<'_>,
    request: &EvaluationRequest<'_>,
    row: &VerdictMemoRow,
) -> Result<()> {
    let vault = evaluator.vault;
    let kind = saved_query_type_byte(vault)?;
    let lane = evaluator.owner_lane(&request.definition.scope)?;
    vault.with_write_txn_grouped(|txn| {
        let current = load_record_in_txn(vault, txn, request.query_ref, kind)?
            .ok_or(Error::EntityNotFound)?;
        if current.definition != *request.definition {
            return Err(Error::ConcurrentWrite("saved query changed during evaluation"));
        }
        if !lane.entities_readable_in_txn(txn, &[request.entity_ref])?[0] {
            return Err(Error::ConcurrentWrite("saved query owner read changed during evaluation"));
        }
        MEMOS.put(&vault.store, txn, &row.key, row)?;
        Ok(())
    })
}
