//! Provider usage, priced by an explicit model-and-revision price table.
use super::{
    BeamError, BeamResult,
    report_model::{CostComponentReport, TokenAccountingSource},
};
use oneiron::{LlmUsage, ModelId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ModelPrice {
    pub input_per_million: f64,
    pub output_per_million: f64,
    pub cache_read_per_million: f64,
    pub cache_write_per_million: f64,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PriceTable {
    pub revision: String,
    pub source: String,
    pub models: BTreeMap<ModelId, ModelPrice>,
}
impl PriceTable {
    pub(super) fn cost(
        &self,
        model: &ModelId,
        usage: &LlmUsage,
        elapsed_us: u64,
    ) -> BeamResult<CostComponentReport> {
        let price = self
            .models
            .get(model)
            .ok_or_else(|| BeamError::Comparability {
                reason: "model has no pinned price".into(),
            })?;
        if self.revision.is_empty()
            || self.source.is_empty()
            || [
                price.input_per_million,
                price.output_per_million,
                price.cache_read_per_million,
                price.cache_write_per_million,
            ]
            .iter()
            .any(|v| !v.is_finite() || *v < 0.0)
            || usage
                .input
                .cache_read
                .checked_add(usage.input.cache_write)
                .is_none_or(|v| v > usage.input.total)
            || usage.raw_provider.is_null()
        {
            return Err(BeamError::Comparability {
                reason: "invalid price pin or missing provider usage".into(),
            });
        }
        let uncached = usage.input.total - usage.input.cache_read - usage.input.cache_write;
        let cost_usd = (uncached as f64 * price.input_per_million
            + usage.input.cache_read as f64 * price.cache_read_per_million
            + usage.input.cache_write as f64 * price.cache_write_per_million
            + usage.output.total as f64 * price.output_per_million)
            / 1_000_000.0;
        if !cost_usd.is_finite() {
            return Err(BeamError::Comparability {
                reason: "usage price overflow".into(),
            });
        }
        Ok(CostComponentReport {
            token_source: TokenAccountingSource::ProviderUsage,
            tokenizer_id: None,
            input_tokens: usage.input.total,
            output_tokens: usage.output.total,
            target_tokens: 0,
            elapsed_us,
            cost_usd,
        })
    }
}
pub(super) fn sum_costs(costs: &[CostComponentReport]) -> BeamResult<CostComponentReport> {
    let mut sum = CostComponentReport {
        token_source: costs
            .first()
            .map_or(TokenAccountingSource::ProviderUsage, |cost| {
                cost.token_source
            }),
        tokenizer_id: costs.first().and_then(|cost| cost.tokenizer_id.clone()),
        input_tokens: 0,
        output_tokens: 0,
        target_tokens: 0,
        elapsed_us: 0,
        cost_usd: 0.0,
    };
    for cost in costs {
        if cost.token_source != sum.token_source || cost.tokenizer_id != sum.tokenizer_id {
            return Err(BeamError::Comparability {
                reason: "cost sum requires matching accounting sources and tokenizers".into(),
            });
        }
        let overflow = || BeamError::Comparability {
            reason: "usage sum overflow".into(),
        };
        sum.input_tokens = sum
            .input_tokens
            .checked_add(cost.input_tokens)
            .ok_or_else(overflow)?;
        sum.output_tokens = sum
            .output_tokens
            .checked_add(cost.output_tokens)
            .ok_or_else(overflow)?;
        sum.target_tokens = sum
            .target_tokens
            .checked_add(cost.target_tokens)
            .ok_or_else(overflow)?;
        sum.elapsed_us = sum
            .elapsed_us
            .checked_add(cost.elapsed_us)
            .ok_or_else(overflow)?;
        sum.cost_usd += cost.cost_usd;
    }
    if !sum.cost_usd.is_finite() {
        return Err(BeamError::Comparability {
            reason: "dollar sum overflow".into(),
        });
    }
    Ok(sum)
}
