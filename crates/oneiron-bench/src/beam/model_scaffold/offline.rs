//! Stage-aware offline accounting for the measured scaffold.
use super::super::{
    llm_host::{ModelCallReceipt, ModelSession},
    model_usage::sum_costs,
    report_model::{CostComponentReport, TokenAccountingSource},
};
use super::{BeamResult, refusal};
use oneiron::CallPurpose;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub(in crate::beam) struct OfflineStages {
    pub(super) ingest: CostComponentReport,
    pub(super) extraction: CostComponentReport,
    pub(super) dreamer_consolidation: CostComponentReport,
    pub(super) index_build: CostComponentReport,
}

pub(super) fn elapsed_cost(elapsed_us: u64) -> CostComponentReport {
    let mut cost = super::super::report::not_applicable_cost();
    cost.elapsed_us = elapsed_us;
    cost
}

// Provider receipts are produced by the same pinned session as the answerer.
// Never infer a provider price from corpus token counts or fixture-declared zeros.
pub(super) fn offline_provider_cost(
    receipts: &[ModelCallReceipt],
    purpose: CallPurpose,
    session: &ModelSession,
) -> BeamResult<CostComponentReport> {
    let costs = receipts
        .iter()
        .filter(|receipt| receipt.purpose == purpose)
        .map(|receipt| {
            session
                .prices
                .cost(&receipt.model, &receipt.usage, receipt.elapsed_us)
        })
        .collect::<BeamResult<Vec<_>>>()?;
    if costs.is_empty() {
        return Ok(super::super::report::not_applicable_cost());
    }
    sum_costs(&costs)
}

pub(super) fn offline_totals(
    stages: &OfflineStages,
    questions: usize,
) -> BeamResult<(CostComponentReport, CostComponentReport)> {
    let parts = [
        &stages.ingest,
        &stages.extraction,
        &stages.dreamer_consolidation,
        &stages.index_build,
    ];
    let overflow = || refusal("offline cost sum overflow");
    let mut total = elapsed_cost(0);
    // Keep a single tokenizer identity only when every counted token uses it.
    let has_provider_tokens = [&stages.extraction, &stages.dreamer_consolidation]
        .iter()
        .any(|cost| cost.input_tokens != 0 || cost.output_tokens != 0);
    if !has_provider_tokens {
        total.token_source = stages.ingest.token_source;
        total.tokenizer_id = stages.ingest.tokenizer_id.clone();
    } else {
        total.token_source = TokenAccountingSource::Mixed;
    }
    for part in parts {
        total.input_tokens = total
            .input_tokens
            .checked_add(part.input_tokens)
            .ok_or_else(overflow)?;
        total.output_tokens = total
            .output_tokens
            .checked_add(part.output_tokens)
            .ok_or_else(overflow)?;
        total.target_tokens = total
            .target_tokens
            .checked_add(part.target_tokens)
            .ok_or_else(overflow)?;
        total.elapsed_us = total
            .elapsed_us
            .checked_add(part.elapsed_us)
            .ok_or_else(overflow)?;
        total.cost_usd += part.cost_usd;
    }
    if !total.cost_usd.is_finite() || questions == 0 {
        return Err(overflow());
    }
    let mut amortized = total.clone();
    let n = questions as u64;
    amortized.input_tokens = amortized.input_tokens.div_ceil(n);
    amortized.output_tokens = amortized.output_tokens.div_ceil(n);
    amortized.target_tokens = amortized.target_tokens.div_ceil(n);
    amortized.elapsed_us = amortized.elapsed_us.div_ceil(n);
    amortized.cost_usd /= questions as f64;
    Ok((total, amortized))
}
