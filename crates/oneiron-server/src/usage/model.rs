//! Usage domain model: modes, events, costs, rollups, counters, and money helpers.
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::codec::UsageError;
use super::keys::{
    MAX_DIMENSION_LEN, MAX_IDEMPOTENCY_KEY_LEN, validate_dimension, validate_non_negative_finite,
    validate_optional_dimension,
};

pub const CREDIT_UNIT_USD: f64 = 0.01;

const TOKENS_PER_MILLION: f64 = 1_000_000.0;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UsageMode {
    #[default]
    Local,
    #[serde(alias = "bring_your_own", alias = "bring-your-own")]
    Byo,
    #[serde(alias = "oneiron-cloud", alias = "cloud")]
    OneironCloud,
}

impl UsageMode {
    pub fn debits_usage(self) -> bool {
        matches!(self, Self::OneironCloud)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Byo => "byo",
            Self::OneironCloud => "oneiron_cloud",
        }
    }
}

impl fmt::Display for UsageMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for UsageMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value
            .trim()
            .to_ascii_lowercase()
            .replace(['-', '_'], "")
            .as_str()
        {
            "local" => Ok(Self::Local),
            "byo" | "bringyourown" => Ok(Self::Byo),
            "cloud" | "oneironcloud" => Ok(Self::OneironCloud),
            _ => Err(format!(
                "expected one of local, byo, oneiron_cloud; got {value:?}"
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UsageEventType {
    #[default]
    Inference,
    Cache,
    Service,
}

impl UsageEventType {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Inference => "inference",
            Self::Cache => "cache",
            Self::Service => "service",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UsageTokenCounts {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UsageCostRates {
    pub input_token_usd_per_million: f64,
    pub output_token_usd_per_million: f64,
    pub cache_read_token_usd_per_million: f64,
    pub cache_write_token_usd_per_million: f64,
}

impl UsageCostRates {
    fn validate(&self) -> Result<(), UsageError> {
        validate_non_negative_finite(
            "costRates.inputTokenUsdPerMillion",
            self.input_token_usd_per_million,
        )?;
        validate_non_negative_finite(
            "costRates.outputTokenUsdPerMillion",
            self.output_token_usd_per_million,
        )?;
        validate_non_negative_finite(
            "costRates.cacheReadTokenUsdPerMillion",
            self.cache_read_token_usd_per_million,
        )?;
        validate_non_negative_finite(
            "costRates.cacheWriteTokenUsdPerMillion",
            self.cache_write_token_usd_per_million,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UsageServiceCost {
    pub service: String,
    pub cost_usd: f64,
}

impl UsageServiceCost {
    fn validate(&self) -> Result<(), UsageError> {
        validate_dimension("serviceCosts.service", &self.service, MAX_DIMENSION_LEN)?;
        validate_non_negative_finite("serviceCosts.costUsd", self.cost_usd)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UsageCostInput {
    #[serde(default)]
    pub token_counts: UsageTokenCounts,
    #[serde(default)]
    pub cost_rates: UsageCostRates,
    #[serde(default)]
    pub service_cost_usd: f64,
    #[serde(default)]
    pub service_costs: Vec<UsageServiceCost>,
}

impl UsageCostInput {
    pub fn calculate(&self) -> Result<UsageCost, UsageError> {
        self.cost_rates.validate()?;
        validate_non_negative_finite("serviceCostUsd", self.service_cost_usd)?;

        let token_cost_usd = normalize_money(
            per_million_cost(
                self.token_counts.input_tokens,
                self.cost_rates.input_token_usd_per_million,
            ) + per_million_cost(
                self.token_counts.output_tokens,
                self.cost_rates.output_token_usd_per_million,
            ),
        );
        let cache_cost_usd = normalize_money(
            per_million_cost(
                self.token_counts.cache_read_tokens,
                self.cost_rates.cache_read_token_usd_per_million,
            ) + per_million_cost(
                self.token_counts.cache_write_tokens,
                self.cost_rates.cache_write_token_usd_per_million,
            ),
        );

        let mut service_cost_usd = self.service_cost_usd;
        for service_cost in &self.service_costs {
            service_cost.validate()?;
            service_cost_usd += service_cost.cost_usd;
        }
        let service_cost_usd = normalize_money(service_cost_usd);
        validate_non_negative_finite("serviceCostUsd", service_cost_usd)?;

        let cost_usd = normalize_money(token_cost_usd + cache_cost_usd + service_cost_usd);
        validate_non_negative_finite("costUsd", cost_usd)?;

        Ok(UsageCost {
            token_cost_usd,
            cache_cost_usd,
            service_cost_usd,
            cost_usd,
            credit_units: credit_units(cost_usd),
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UsageCost {
    pub token_cost_usd: f64,
    pub cache_cost_usd: f64,
    pub service_cost_usd: f64,
    pub cost_usd: f64,
    pub credit_units: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UsageEvent {
    pub tenant_id: String,
    pub vault_id: String,
    pub idempotency_key: String,
    #[serde(default)]
    pub source: Option<UsageMode>,
    #[serde(default)]
    pub event_type: UsageEventType,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub occurred_at: Option<u64>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub token_counts: UsageTokenCounts,
    #[serde(default)]
    pub cost_rates: UsageCostRates,
    #[serde(default)]
    pub service_cost_usd: f64,
    #[serde(default)]
    pub service_costs: Vec<UsageServiceCost>,
}

impl UsageEvent {
    pub fn resolved_source(&self, configured_mode: UsageMode) -> UsageMode {
        self.source.unwrap_or(configured_mode)
    }

    pub fn cost_input(&self) -> UsageCostInput {
        UsageCostInput {
            token_counts: self.token_counts.clone(),
            cost_rates: self.cost_rates.clone(),
            service_cost_usd: self.service_cost_usd,
            service_costs: self.service_costs.clone(),
        }
    }

    pub(super) fn validate(&self) -> Result<(), UsageError> {
        validate_dimension("tenantId", &self.tenant_id, MAX_DIMENSION_LEN)?;
        validate_dimension("vaultId", &self.vault_id, MAX_DIMENSION_LEN)?;
        validate_dimension(
            "idempotencyKey",
            &self.idempotency_key,
            MAX_IDEMPOTENCY_KEY_LEN,
        )?;
        validate_optional_dimension("role", self.role.as_deref())?;
        validate_optional_dimension("agentId", self.agent_id.as_deref())?;
        validate_optional_dimension("model", self.model.as_deref())?;
        validate_optional_dimension("service", self.service.as_deref())?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UsageDebit {
    pub idempotency_key: String,
    pub cost_usd: f64,
    pub credit_units: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UsageRecordResult {
    pub recorded: bool,
    pub replayed: bool,
    pub source: UsageMode,
    pub cost: UsageCost,
    pub debit: Option<UsageDebit>,
    pub tenant_rollup: Option<UsageRollup>,
    pub vault_rollup: Option<UsageRollup>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UsageRollup {
    pub tenant_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault_id: Option<String>,
    pub counters: UsageCounter,
    pub agents: BTreeMap<String, UsageCounter>,
    pub models: BTreeMap<String, UsageCounter>,
    pub services: BTreeMap<String, UsageCounter>,
}

impl UsageRollup {
    pub fn tenant(tenant_id: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            vault_id: None,
            counters: UsageCounter::default(),
            agents: BTreeMap::new(),
            models: BTreeMap::new(),
            services: BTreeMap::new(),
        }
    }

    pub fn vault(tenant_id: impl Into<String>, vault_id: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            vault_id: Some(vault_id.into()),
            counters: UsageCounter::default(),
            agents: BTreeMap::new(),
            models: BTreeMap::new(),
            services: BTreeMap::new(),
        }
    }

    pub(super) fn add_event(&mut self, event: &UsageEvent, cost: &UsageCost) {
        self.counters.add(&event.token_counts, cost);
        add_breakdown(
            &mut self.agents,
            event.agent_id.as_deref(),
            &event.token_counts,
            cost,
        );
        add_breakdown(
            &mut self.models,
            event.model.as_deref(),
            &event.token_counts,
            cost,
        );
        add_breakdown(
            &mut self.services,
            event.service.as_deref(),
            &event.token_counts,
            cost,
        );
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UsageCounter {
    pub event_count: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub token_cost_usd: f64,
    pub cache_cost_usd: f64,
    pub service_cost_usd: f64,
    pub cost_usd: f64,
    pub credit_units: f64,
}

impl UsageCounter {
    fn add(&mut self, tokens: &UsageTokenCounts, cost: &UsageCost) {
        self.event_count = self.event_count.saturating_add(1);
        self.input_tokens = self.input_tokens.saturating_add(tokens.input_tokens);
        self.output_tokens = self.output_tokens.saturating_add(tokens.output_tokens);
        self.cache_read_tokens = self
            .cache_read_tokens
            .saturating_add(tokens.cache_read_tokens);
        self.cache_write_tokens = self
            .cache_write_tokens
            .saturating_add(tokens.cache_write_tokens);
        self.token_cost_usd = normalize_money(self.token_cost_usd + cost.token_cost_usd);
        self.cache_cost_usd = normalize_money(self.cache_cost_usd + cost.cache_cost_usd);
        self.service_cost_usd = normalize_money(self.service_cost_usd + cost.service_cost_usd);
        self.cost_usd = normalize_money(self.cost_usd + cost.cost_usd);
        self.credit_units = credit_units(self.cost_usd);
    }
}

pub(super) fn per_million_cost(tokens: u64, usd_per_million: f64) -> f64 {
    tokens as f64 * usd_per_million / TOKENS_PER_MILLION
}

pub(super) fn credit_units(cost_usd: f64) -> f64 {
    normalize_money(cost_usd / CREDIT_UNIT_USD)
}

pub(super) fn normalize_money(value: f64) -> f64 {
    const SCALE: f64 = 1_000_000_000_000.0;
    (value * SCALE).round() / SCALE
}

fn add_breakdown(
    breakdown: &mut BTreeMap<String, UsageCounter>,
    dimension: Option<&str>,
    tokens: &UsageTokenCounts,
    cost: &UsageCost,
) {
    let Some(dimension) = dimension else {
        return;
    };
    breakdown
        .entry(dimension.to_owned())
        .or_default()
        .add(tokens, cost);
}
