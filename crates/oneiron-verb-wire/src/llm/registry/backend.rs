//! Moved from `crates/oneiron/src/llm/registry/backend.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::llm::registry::invalid;
use crate::llm::registry::price;
use oneiron_base::error::Result;
use oneiron_model::llm::LlmCatalogCost;
use oneiron_model::llm::LlmUsage;
use oneiron_model::llm::ModelId;
use serde::Deserialize;
use serde::Serialize;

/// A revision of the backend's serving configuration, not just the upstream weights.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelBackendPin {
    pub model: ModelId,
    pub backend: String,
    pub serving_revision: String,
    pub quantization: Option<String>,
    pub context_window_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PricedModelBackend {
    pub pin: ModelBackendPin,
    pub price: LlmCatalogCost,
}

/// Prices and totals use the same monetary unit as the registered catalog price.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelCostReceipt {
    pub backend: ModelBackendPin,
    pub price: LlmCatalogCost,
    pub usage: LlmUsage,
    pub units: u64,
    pub cost: f64,
    pub cost_per_thousand: f64,
}

impl ModelBackendPin {
    pub fn validate(&self) -> Result<()> {
        if [&self.backend, &self.serving_revision]
            .iter()
            .any(|s| s.trim().is_empty() || s.len() > 256 || s.contains('\0'))
            || self
                .quantization
                .as_ref()
                .is_some_and(|s| s.trim().is_empty() || s.len() > 256 || s.contains('\0'))
            || self.context_window_tokens == 0
        {
            return Err(invalid("invalid model backend pin"));
        }
        Ok(())
    }
}

pub fn amount(value: &str) -> Result<f64> {
    if !price(value) {
        return Err(invalid("invalid backend price"));
    }
    value
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite() && *value >= 0.0)
        .ok_or_else(|| invalid("invalid backend price"))
}

/// The catalog's monetary quote applied to the reported token usage. A missing
/// cache price is unknown when that cache was used, not a free cache read.
pub fn catalog_usage_cost(price: &LlmCatalogCost, usage: &LlmUsage) -> Result<f64> {
    let cached = usage
        .input
        .cache_read
        .checked_add(usage.input.cache_write)
        .ok_or_else(|| invalid("model usage overflow"))?;
    let uncached = usage
        .input
        .total
        .checked_sub(cached)
        .ok_or_else(|| invalid("cache usage exceeds input usage"))?;
    let cache_cost = |tokens: u64, value: &Option<String>| -> Result<f64> {
        if tokens == 0 {
            return Ok(0.0);
        }
        Ok(tokens as f64
            * amount(
                value
                    .as_deref()
                    .ok_or_else(|| invalid("cache price missing"))?,
            )?)
    };
    let cost = (uncached as f64 * amount(&price.input_per_million)?
        + usage.output.total as f64 * amount(&price.output_per_million)?
        + cache_cost(usage.input.cache_read, &price.cache_read_per_million)?
        + cache_cost(usage.input.cache_write, &price.cache_write_per_million)?)
        / 1_000_000.0;
    if !cost.is_finite() {
        return Err(invalid("model cost overflow"));
    }
    Ok(cost)
}

impl PricedModelBackend {
    pub fn validate(&self) -> Result<()> {
        self.pin.validate()?;
        amount(&self.price.input_per_million)?;
        amount(&self.price.output_per_million)?;
        for value in [
            &self.price.cache_read_per_million,
            &self.price.cache_write_per_million,
        ]
        .into_iter()
        .flatten()
        {
            amount(value)?;
        }
        Ok(())
    }

    /// Cache tokens are subsets of input.total; reasoning is inside output.total.
    /// Missing cache prices do not silently turn a measured bill into an estimate.
    pub fn cost_receipt(&self, usage: LlmUsage, units: u64) -> Result<ModelCostReceipt> {
        self.validate()?;
        if units == 0 {
            return Err(invalid("a cost receipt needs units"));
        }
        let cost = catalog_usage_cost(&self.price, &usage)?;
        let cost_per_thousand = cost * 1_000.0 / units as f64;
        if !cost.is_finite() || !cost_per_thousand.is_finite() {
            return Err(invalid("model cost overflow"));
        }
        Ok(ModelCostReceipt {
            backend: self.pin.clone(),
            price: self.price.clone(),
            usage,
            units,
            cost,
            cost_per_thousand,
        })
    }
}
