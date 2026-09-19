//! Provider-list money facts and per-vault usage counters.
use super::{
    codec::UsageError,
    keys::{
        MAX_DIMENSION_LEN, MAX_IDEMPOTENCY_KEY_LEN, validate_dimension, validate_optional_dimension,
    },
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt, str::FromStr};
use utoipa::ToSchema;

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

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UsageTokenCounts {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
}

/// Fixed-point provider money: one amount unit is 10^-9 of the named currency.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Money {
    pub amount: u64,
    pub currency: String,
    pub price_table_snapshot: String,
}
impl Money {
    pub(super) fn validate(&self) -> Result<(), UsageError> {
        if self.currency.len() != 3 || !self.currency.bytes().all(|b| b.is_ascii_uppercase()) {
            return Err(UsageError::InvalidField {
                field: "currency",
                message: "expected a three-letter currency",
            });
        }
        validate_dimension(
            "priceTableSnapshot",
            &self.price_table_snapshot,
            MAX_DIMENSION_LEN,
        )
    }
}

/// Provider list rates in nano-currency units per million tokens.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UsageCostRates {
    pub currency: String,
    pub price_table_snapshot: String,
    pub input_per_million: u64,
    pub output_per_million: u64,
    pub cache_read_per_million: u64,
    pub cache_write_per_million: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UsageCostInput {
    pub token_counts: UsageTokenCounts,
    pub cost_rates: UsageCostRates,
    /// Additional provider list cost in the rate table's currency.
    #[serde(default)]
    pub service_amount: u64,
}
impl UsageCostInput {
    pub fn calculate(&self) -> Result<Money, UsageError> {
        let t = &self.token_counts;
        let r = &self.cost_rates;
        let numerator = [
            (t.input_tokens, r.input_per_million),
            (t.output_tokens, r.output_per_million),
            (t.cache_read_tokens, r.cache_read_per_million),
            (t.cache_write_tokens, r.cache_write_per_million),
        ]
        .into_iter()
        .try_fold(0u128, |sum, (qty, rate)| {
            sum.checked_add(u128::from(qty) * u128::from(rate))
                .ok_or(UsageError::Overflow)
        })?;
        let tokens = numerator.div_ceil(1_000_000);
        let amount = u64::try_from(tokens)
            .map_err(|_| UsageError::Overflow)?
            .checked_add(self.service_amount)
            .ok_or(UsageError::Overflow)?;
        let money = Money {
            amount,
            currency: r.currency.clone(),
            price_table_snapshot: r.price_table_snapshot.clone(),
        };
        money.validate()?;
        Ok(money)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UsageEvent {
    pub owner: String,
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
    pub cost_rates: UsageCostRates,
    #[serde(default)]
    pub service_amount: u64,
}
impl UsageEvent {
    pub fn resolved_source(&self, configured: UsageMode) -> UsageMode {
        self.source.unwrap_or(configured)
    }
    pub fn cost_input(&self) -> UsageCostInput {
        UsageCostInput {
            token_counts: self.token_counts.clone(),
            cost_rates: self.cost_rates.clone(),
            service_amount: self.service_amount,
        }
    }
    pub(super) fn validate(&self) -> Result<(), UsageError> {
        validate_dimension("owner", &self.owner, MAX_DIMENSION_LEN)?;
        validate_dimension("vaultId", &self.vault_id, MAX_DIMENSION_LEN)?;
        validate_dimension(
            "idempotencyKey",
            &self.idempotency_key,
            MAX_IDEMPOTENCY_KEY_LEN,
        )?;
        for (field, value) in [
            ("role", &self.role),
            ("agentId", &self.agent_id),
            ("model", &self.model),
            ("service", &self.service),
        ] {
            validate_optional_dimension(field, value.as_deref())?;
        }
        super::keys::validate_key(&super::keys::usage_event_key(
            &self.owner,
            &self.vault_id,
            &self.idempotency_key,
        ))
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UsageRecordResult {
    pub recorded: bool,
    pub replayed: bool,
    pub source: UsageMode,
    pub cost: Money,
    pub vault_rollup: Option<UsageRollup>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UsageRollup {
    pub owner: String,
    pub vault_id: String,
    pub counters: UsageCounter,
    pub agents: BTreeMap<String, UsageCounter>,
    pub models: BTreeMap<String, UsageCounter>,
    pub services: BTreeMap<String, UsageCounter>,
}
impl UsageRollup {
    pub fn vault(owner: impl Into<String>, vault_id: impl Into<String>) -> Self {
        Self {
            owner: owner.into(),
            vault_id: vault_id.into(),
            counters: UsageCounter::default(),
            agents: BTreeMap::new(),
            models: BTreeMap::new(),
            services: BTreeMap::new(),
        }
    }
    pub(super) fn add_event(&mut self, event: &UsageEvent, cost: &Money) -> Result<(), UsageError> {
        self.counters.add(&event.token_counts, cost)?;
        for (map, key) in [
            (&mut self.agents, &event.agent_id),
            (&mut self.models, &event.model),
            (&mut self.services, &event.service),
        ] {
            if let Some(key) = key {
                map.entry(key.clone())
                    .or_default()
                    .add(&event.token_counts, cost)?;
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UsageCounter {
    pub event_count: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    /// Different currencies are never added together.
    pub amounts_by_currency: BTreeMap<String, u64>,
}
impl UsageCounter {
    fn add(&mut self, t: &UsageTokenCounts, cost: &Money) -> Result<(), UsageError> {
        for (dest, value) in [
            (&mut self.event_count, 1),
            (&mut self.input_tokens, t.input_tokens),
            (&mut self.output_tokens, t.output_tokens),
            (&mut self.cache_read_tokens, t.cache_read_tokens),
            (&mut self.cache_write_tokens, t.cache_write_tokens),
        ] {
            *dest = dest.checked_add(value).ok_or(UsageError::Overflow)?;
        }
        let amount = self
            .amounts_by_currency
            .entry(cost.currency.clone())
            .or_default();
        *amount = amount
            .checked_add(cost.amount)
            .ok_or(UsageError::Overflow)?;
        Ok(())
    }
}
