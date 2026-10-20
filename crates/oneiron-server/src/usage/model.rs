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
impl UsageTokenCounts {
    /// The measured count in one cache dimension.
    pub fn cache_tokens(&self, dimension: CacheDimension) -> u64 {
        match dimension {
            CacheDimension::CacheRead => self.cache_read_tokens,
            CacheDimension::CacheWrite => self.cache_write_tokens,
        }
    }
}

/// A cached prompt-token dimension a list price may quote a rate for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CacheDimension {
    CacheRead,
    CacheWrite,
}

/// Why a call has no price, as its settlement recorded it: the first of
/// these that holds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnpricedReason {
    /// The call measured no tokens: no usage block, or every count zero.
    /// Nothing is priced, and a service quantity it reported stays on its run.
    NoUsage,
    /// The call measured tokens, but no rates were frozen on it at admission:
    /// no host override names its offer, and the catalog has no row or no
    /// price that converts for its model (a paid connector call has none).
    /// The event's `model` names the model.
    UnpricedModel,
    /// The rates frozen on the call quote no rate for these cache dimensions,
    /// each measured above zero, listed once each in order. Every other count
    /// had a quoted rate.
    UnquotedCache { dimensions: Vec<CacheDimension> },
    /// The rates frozen on the call quote every count it measured, and its
    /// price at them does not fit in an amount (FIX 6407). The event keeps
    /// its counts and those rates; the ledger, not the settlement, names
    /// this when it records the call.
    PriceOverflow,
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
        validate_price_names(&self.currency, &self.price_table_snapshot)
    }
}

/// A three-letter currency and a price-table snapshot id that fits.
fn validate_price_names(currency: &str, price_table_snapshot: &str) -> Result<(), UsageError> {
    if currency.len() != 3 || !currency.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(UsageError::InvalidField {
            field: "currency",
            message: "expected a three-letter currency",
        });
    }
    validate_dimension(
        "priceTableSnapshot",
        price_table_snapshot,
        MAX_DIMENSION_LEN,
    )
}

/// Provider list rates in nano-currency units per million tokens.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UsageCostRates {
    pub currency: String,
    pub price_table_snapshot: String,
    pub input_per_million: u64,
    pub output_per_million: u64,
    /// `None` when the price table quotes no cache rate: unknown, never
    /// zero. `Some(0)` is a quoted free rate.
    #[serde(default)]
    pub cache_read_per_million: Option<u64>,
    #[serde(default)]
    pub cache_write_per_million: Option<u64>,
}
impl UsageCostRates {
    /// Checks the currency and price-table snapshot these rates name, before
    /// any count is priced at them: a bad name is never read as an overflow.
    pub(super) fn validate(&self) -> Result<(), UsageError> {
        validate_price_names(&self.currency, &self.price_table_snapshot)
    }

    /// Whether these rates price `counts`: every count above zero has a
    /// quoted rate. Cached tokens with no quoted cache rate have no price.
    pub fn prices(&self, counts: &UsageTokenCounts) -> bool {
        (counts.cache_read_tokens == 0 || self.cache_read_per_million.is_some())
            && (counts.cache_write_tokens == 0 || self.cache_write_per_million.is_some())
    }

    /// The cache dimensions `counts` measured above zero that these rates
    /// quote no rate for, in order: empty exactly when they price `counts`.
    pub fn unquoted_cache(&self, counts: &UsageTokenCounts) -> Vec<CacheDimension> {
        [
            (CacheDimension::CacheRead, self.cache_read_per_million),
            (CacheDimension::CacheWrite, self.cache_write_per_million),
        ]
        .into_iter()
        .filter(|(dimension, rate)| rate.is_none() && counts.cache_tokens(*dimension) > 0)
        .map(|(dimension, _)| dimension)
        .collect()
    }
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
        if !r.prices(t) {
            return Err(UsageError::InvalidField {
                field: "costRates",
                message: "a measured cache count needs its quoted rate",
            });
        }
        // Past that check an unquoted rate only meets a zero count.
        let numerator = [
            (t.input_tokens, r.input_per_million),
            (t.output_tokens, r.output_per_million),
            (t.cache_read_tokens, r.cache_read_per_million.unwrap_or(0)),
            (t.cache_write_tokens, r.cache_write_per_million.unwrap_or(0)),
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
/// Attribution for one admitted physical call: the serving host's own on a
/// record its engine wrote, the poster's on a posted one (FIX 5724).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UsageRun {
    pub instance: String,
    pub run: String,
    pub revision: u32,
    pub lease: String,
    pub offer: String,
    pub route: String,
    pub catalog_revision: Option<String>,
    #[schema(value_type = String)]
    pub payer: oneiron::llm::run_admission::Payer,
    /// The PERSON a room-paid call billed (OF-531), as hex; `None` when no
    /// room paid.
    pub payer_person: Option<String>,
    /// The root spend scope whose payer consent named that PERSON.
    pub payer_scope: Option<String>,
    /// The payer-needed ask on which the owners approved billing the vault,
    /// when the PERSON's own account could not be resolved.
    pub payer_ask: Option<u64>,
    /// The label the call was admitted with (FIX 4453): its envelope
    /// purpose, or a paid connector call's bound item's; `None` for a paid
    /// connector call on an unbound run.
    #[serde(default)]
    pub purpose: Option<String>,
    /// The free-time cycle, item and spend scope a bound run's call served:
    /// as the engine stamped them before the run began on a record it wrote,
    /// as the poster stamped them on a posted one; `None` on every unbound
    /// run.
    #[serde(default)]
    pub cycle: Option<String>,
    #[serde(default)]
    pub item: Option<String>,
    #[serde(default)]
    pub spend_scope: Option<String>,
    pub reserved_units: u64,
    pub settled_units: u64,
    pub unit: String,
    pub usage_reported: bool,
    pub service_quantity: Option<u64>,
    pub allocation: Option<UsageAllocation>,
    pub settlement_refused: bool,
}

/// The allocation held at admission, not whichever generation is live later.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UsageAllocation {
    pub id: String,
    pub generation: u64,
    pub reserved_units: u64,
    pub settled_units: u64,
    pub unit: String,
    pub settlement_refused: bool,
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
    /// Absent when only quantities are known, including custom-key endpoints.
    #[serde(default)]
    pub cost_rates: Option<UsageCostRates>,
    /// Why the call has no price, when its settlement knew: `None` on a
    /// priced call, and on one whose record names no reason.
    #[serde(default)]
    pub unpriced: Option<UnpricedReason>,
    #[serde(default)]
    pub service_amount: u64,
    #[serde(default)]
    pub run: Option<UsageRun>,
}
impl UsageEvent {
    pub fn resolved_source(&self, configured: UsageMode) -> UsageMode {
        self.source.unwrap_or(configured)
    }
    pub fn cost_input(&self) -> Option<UsageCostInput> {
        self.cost_rates.as_ref().map(|rates| UsageCostInput {
            token_counts: self.token_counts.clone(),
            cost_rates: rates.clone(),
            service_amount: self.service_amount,
        })
    }
    pub(super) fn validate(&self) -> Result<(), UsageError> {
        if self.cost_rates.is_none() && self.service_amount != 0 {
            return Err(UsageError::InvalidField {
                field: "serviceAmount",
                message: "requires a currency and price-table snapshot in costRates",
            });
        }
        if let Some(rates) = &self.cost_rates {
            rates.validate()?;
        }
        // Only the event's own rates establish a price overflow: they quote
        // each measured count, and its price at them does not fit.
        if self.unpriced == Some(UnpricedReason::PriceOverflow)
            && !self
                .cost_input()
                .is_some_and(|input| matches!(input.calculate(), Err(UsageError::Overflow)))
        {
            return Err(UsageError::InvalidField {
                field: "unpriced",
                message: "price_overflow names an event whose costRates quote each measured \
                          count and price it past what an amount holds",
            });
        }
        if let Some(UnpricedReason::UnquotedCache { dimensions }) = &self.unpriced
            && (self.cost_rates.is_some()
                || dimensions.is_empty()
                || !dimensions.is_sorted_by(|a, b| a < b)
                || dimensions
                    .iter()
                    .any(|dimension| self.token_counts.cache_tokens(*dimension) == 0))
        {
            return Err(UsageError::InvalidField {
                field: "unpriced",
                message: "names each unquoted cache dimension once, in order, each measured, \
                          on an event with no costRates",
            });
        }
        let has_tokens = self.token_counts != UsageTokenCounts::default();
        if let Some(reason @ (UnpricedReason::NoUsage | UnpricedReason::UnpricedModel)) =
            &self.unpriced
            && (self.cost_rates.is_some()
                || has_tokens != matches!(reason, UnpricedReason::UnpricedModel))
        {
            return Err(UsageError::InvalidField {
                field: "unpriced",
                message: "no_usage names an event with every count zero, unpriced_model one \
                          with a token count, each with no costRates",
            });
        }
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
        if let Some(run) = &self.run {
            for (field, value) in [
                ("run.purpose", &run.purpose),
                ("run.cycle", &run.cycle),
                ("run.item", &run.item),
                ("run.spendScope", &run.spend_scope),
            ] {
                validate_optional_dimension(field, value.as_deref())?;
            }
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
    pub cost: Option<Money>,
    /// Why the call has no price, as its durable record names it: on a
    /// replay, the first write's reason.
    pub unpriced: Option<UnpricedReason>,
    pub vault_rollup: Option<UsageRollup>,
    /// Whether `vault_rollup` sums every recorded call. The call is recorded
    /// whatever this says.
    pub rollup_status: UsageRollupStatus,
}

/// How far a vault rollup can be read as the sum of its recorded calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UsageRollupStatus {
    /// The counters sum every recorded call. An unpriced call adds its
    /// counts and no money: unknown is never zero.
    Current,
    /// A sum would pass what a counter holds: the counters stop before the
    /// call that would carry one past it, a floor and never the total.
    ArithmeticOverflow,
    /// The rollup could not be read or brought up to date; the call itself
    /// is recorded.
    Unavailable,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UsageRollup {
    pub owner: String,
    pub vault_id: String,
    /// [`UsageRollupStatus::Current`] or
    /// [`UsageRollupStatus::ArithmeticOverflow`].
    pub status: UsageRollupStatus,
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
            status: UsageRollupStatus::Current,
            counters: UsageCounter::default(),
            agents: BTreeMap::new(),
            models: BTreeMap::new(),
            services: BTreeMap::new(),
        }
    }
    /// Adds one call to the vault's counters and to its agent's, model's
    /// and service's. Every sum is checked before any is kept: on an
    /// overflow the rollup is left as it was.
    pub(super) fn add_event(
        &mut self,
        event: &UsageEvent,
        cost: Option<&Money>,
    ) -> Result<(), UsageError> {
        let counts = &event.token_counts;
        let counters = self.counters.clone().added(counts, cost)?;
        let agent = added_entry(&self.agents, event.agent_id.as_deref(), counts, cost)?;
        let model = added_entry(&self.models, event.model.as_deref(), counts, cost)?;
        let service = added_entry(&self.services, event.service.as_deref(), counts, cost)?;
        self.counters = counters;
        for (map, entry) in [
            (&mut self.agents, agent),
            (&mut self.models, model),
            (&mut self.services, service),
        ] {
            if let Some((key, counter)) = entry {
                map.insert(key, counter);
            }
        }
        Ok(())
    }
}
/// `key`'s counter in `map` with one call added, `None` when the call names
/// no key there.
fn added_entry(
    map: &BTreeMap<String, UsageCounter>,
    key: Option<&str>,
    counts: &UsageTokenCounts,
    cost: Option<&Money>,
) -> Result<Option<(String, UsageCounter)>, UsageError> {
    let Some(key) = key else {
        return Ok(None);
    };
    let counter = map.get(key).cloned().unwrap_or_default();
    Ok(Some((key.to_owned(), counter.added(counts, cost)?)))
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
    /// This counter with one call's counts and money added, or an overflow
    /// when a sum would pass what its field holds.
    fn added(mut self, t: &UsageTokenCounts, cost: Option<&Money>) -> Result<Self, UsageError> {
        for (dest, value) in [
            (&mut self.event_count, 1),
            (&mut self.input_tokens, t.input_tokens),
            (&mut self.output_tokens, t.output_tokens),
            (&mut self.cache_read_tokens, t.cache_read_tokens),
            (&mut self.cache_write_tokens, t.cache_write_tokens),
        ] {
            *dest = dest.checked_add(value).ok_or(UsageError::Overflow)?;
        }
        if let Some(cost) = cost {
            let amount = self
                .amounts_by_currency
                .entry(cost.currency.clone())
                .or_default();
            *amount = amount
                .checked_add(cost.amount)
                .ok_or(UsageError::Overflow)?;
        }
        Ok(self)
    }
}
