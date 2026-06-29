use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

pub const CREDIT_UNIT_USD: f64 = 0.01;

const USAGE_EVENT_PREFIX: &str = "usage:event:";
const USAGE_TENANT_ROLLUP_PREFIX: &str = "usage:rollup:tenant:";
const USAGE_VAULT_ROLLUP_PREFIX: &str = "usage:rollup:vault:";
const MAX_DIMENSION_LEN: usize = 256;
const MAX_IDEMPOTENCY_KEY_LEN: usize = 256;
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

    fn validate(&self) -> Result<(), UsageError> {
        validate_dimension("tenantId", &self.tenant_id, MAX_DIMENSION_LEN)?;
        validate_dimension("vaultId", &self.vault_id, MAX_DIMENSION_LEN)?;
        validate_dimension(
            "idempotencyKey",
            &self.idempotency_key,
            MAX_IDEMPOTENCY_KEY_LEN,
        )?;
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

    fn add_event(&mut self, event: &UsageEvent, cost: &UsageCost) {
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

#[derive(Clone)]
pub struct UsageLedger {
    vault: Arc<oneiron::Vault>,
    lock: Arc<Mutex<()>>,
}

impl UsageLedger {
    pub fn new(vault: Arc<oneiron::Vault>) -> Self {
        Self {
            vault,
            lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn record_event(
        &self,
        event: UsageEvent,
        configured_mode: UsageMode,
    ) -> Result<UsageRecordResult, UsageError> {
        event.validate()?;
        let source = event.resolved_source(configured_mode);
        let cost = event.cost_input().calculate()?;
        if !configured_mode.debits_usage() || !source.debits_usage() {
            return Ok(UsageRecordResult {
                recorded: false,
                replayed: false,
                source,
                cost,
                debit: None,
                tenant_rollup: None,
                vault_rollup: None,
            });
        }

        let _guard = self.lock.lock().map_err(|_| UsageError::LockPoisoned)?;
        let event_key = usage_event_key(&event.tenant_id, &event.vault_id, &event.idempotency_key);
        if let Some(entry) = self.get_entry(&event_key)? {
            return self.replayed_result(entry);
        }

        let debit = UsageDebit {
            idempotency_key: event.idempotency_key.clone(),
            cost_usd: cost.cost_usd,
            credit_units: cost.credit_units,
        };
        let entry = StoredUsageEvent {
            event: event.clone(),
            source,
            cost: cost.clone(),
            debit: debit.clone(),
            recorded_at: now_secs(),
        };

        let tenant_key = tenant_rollup_key(&event.tenant_id);
        let vault_key = vault_rollup_key(&event.tenant_id, &event.vault_id);
        let mut tenant_rollup = self
            .get_rollup(&tenant_key)?
            .unwrap_or_else(|| UsageRollup::tenant(event.tenant_id.clone()));
        let mut vault_rollup = self
            .get_rollup(&vault_key)?
            .unwrap_or_else(|| UsageRollup::vault(event.tenant_id.clone(), event.vault_id.clone()));
        tenant_rollup.add_event(&event, &cost);
        vault_rollup.add_event(&event, &cost);

        self.put_rollup(&tenant_key, &tenant_rollup)?;
        self.put_rollup(&vault_key, &vault_rollup)?;
        self.put_entry(&event_key, &entry)?;

        Ok(UsageRecordResult {
            recorded: true,
            replayed: false,
            source,
            cost,
            debit: Some(debit),
            tenant_rollup: Some(tenant_rollup),
            vault_rollup: Some(vault_rollup),
        })
    }

    pub fn tenant_rollup(&self, tenant_id: &str) -> Result<Option<UsageRollup>, UsageError> {
        validate_dimension("tenantId", tenant_id, MAX_DIMENSION_LEN)?;
        let _guard = self.lock.lock().map_err(|_| UsageError::LockPoisoned)?;
        self.get_rollup(&tenant_rollup_key(tenant_id))
    }

    pub fn vault_rollup(
        &self,
        tenant_id: &str,
        vault_id: &str,
    ) -> Result<Option<UsageRollup>, UsageError> {
        validate_dimension("tenantId", tenant_id, MAX_DIMENSION_LEN)?;
        validate_dimension("vaultId", vault_id, MAX_DIMENSION_LEN)?;
        let _guard = self.lock.lock().map_err(|_| UsageError::LockPoisoned)?;
        self.get_rollup(&vault_rollup_key(tenant_id, vault_id))
    }

    fn replayed_result(&self, entry: StoredUsageEvent) -> Result<UsageRecordResult, UsageError> {
        Ok(UsageRecordResult {
            recorded: false,
            replayed: true,
            source: entry.source,
            cost: entry.cost,
            debit: Some(entry.debit),
            tenant_rollup: self.get_rollup(&tenant_rollup_key(&entry.event.tenant_id))?,
            vault_rollup: self.get_rollup(&vault_rollup_key(
                &entry.event.tenant_id,
                &entry.event.vault_id,
            ))?,
        })
    }

    fn get_entry(&self, key: &str) -> Result<Option<StoredUsageEvent>, UsageError> {
        let Some(raw) = self.vault.sync_state_get(key)? else {
            return Ok(None);
        };
        rmp_serde::from_slice(&raw)
            .map(Some)
            .map_err(UsageError::decode)
    }

    fn put_entry(&self, key: &str, entry: &StoredUsageEvent) -> Result<(), UsageError> {
        let raw = rmp_serde::to_vec_named(entry).map_err(UsageError::encode)?;
        self.vault.sync_state_put(key, &raw)?;
        Ok(())
    }

    fn get_rollup(&self, key: &str) -> Result<Option<UsageRollup>, UsageError> {
        let Some(raw) = self.vault.sync_state_get(key)? else {
            return Ok(None);
        };
        rmp_serde::from_slice(&raw)
            .map(Some)
            .map_err(UsageError::decode)
    }

    fn put_rollup(&self, key: &str, rollup: &UsageRollup) -> Result<(), UsageError> {
        let raw = rmp_serde::to_vec_named(rollup).map_err(UsageError::encode)?;
        self.vault.sync_state_put(key, &raw)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredUsageEvent {
    event: UsageEvent,
    source: UsageMode,
    cost: UsageCost,
    debit: UsageDebit,
    recorded_at: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum UsageError {
    #[error("{field}: {message}")]
    InvalidField {
        field: &'static str,
        message: &'static str,
    },
    #[error("usage ledger storage error: {0}")]
    Storage(#[from] oneiron::Error),
    #[error("usage ledger encode error: {0}")]
    Encode(rmp_serde::encode::Error),
    #[error("usage ledger decode error: {0}")]
    Decode(rmp_serde::decode::Error),
    #[error("usage ledger lock poisoned")]
    LockPoisoned,
}

impl UsageError {
    fn encode(error: rmp_serde::encode::Error) -> Self {
        Self::Encode(error)
    }

    fn decode(error: rmp_serde::decode::Error) -> Self {
        Self::Decode(error)
    }

    pub fn field(&self) -> Option<&'static str> {
        match self {
            Self::InvalidField { field, .. } => Some(field),
            _ => None,
        }
    }
}

fn per_million_cost(tokens: u64, usd_per_million: f64) -> f64 {
    tokens as f64 * usd_per_million / TOKENS_PER_MILLION
}

fn credit_units(cost_usd: f64) -> f64 {
    normalize_money(cost_usd / CREDIT_UNIT_USD)
}

fn normalize_money(value: f64) -> f64 {
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

fn usage_event_key(tenant_id: &str, vault_id: &str, idempotency_key: &str) -> String {
    format!(
        "{USAGE_EVENT_PREFIX}{}:{}:{}",
        key_part(tenant_id),
        key_part(vault_id),
        key_part(idempotency_key)
    )
}

fn tenant_rollup_key(tenant_id: &str) -> String {
    format!("{USAGE_TENANT_ROLLUP_PREFIX}{}", key_part(tenant_id))
}

fn vault_rollup_key(tenant_id: &str, vault_id: &str) -> String {
    format!(
        "{USAGE_VAULT_ROLLUP_PREFIX}{}:{}",
        key_part(tenant_id),
        key_part(vault_id)
    )
}

fn key_part(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = value.as_bytes();
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn validate_optional_dimension(field: &'static str, value: Option<&str>) -> Result<(), UsageError> {
    if let Some(value) = value {
        validate_dimension(field, value, MAX_DIMENSION_LEN)?;
    }
    Ok(())
}

fn validate_dimension(field: &'static str, value: &str, max_len: usize) -> Result<(), UsageError> {
    if value.trim().is_empty() {
        return Err(UsageError::InvalidField {
            field,
            message: "must not be empty",
        });
    }
    if value.len() > max_len {
        return Err(UsageError::InvalidField {
            field,
            message: "is too long",
        });
    }
    Ok(())
}

fn validate_non_negative_finite(field: &'static str, value: f64) -> Result<(), UsageError> {
    if !value.is_finite() {
        return Err(UsageError::InvalidField {
            field,
            message: "must be finite",
        });
    }
    if value < 0.0 {
        return Err(UsageError::InvalidField {
            field,
            message: "must not be negative",
        });
    }
    Ok(())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ledger() -> (tempfile::TempDir, UsageLedger) {
        let dir = tempfile::tempdir().unwrap();
        let vault =
            Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
        (dir, UsageLedger::new(vault))
    }

    fn cloud_event(idempotency_key: &str) -> UsageEvent {
        UsageEvent {
            tenant_id: "tenant-a".to_owned(),
            vault_id: "vault-a".to_owned(),
            idempotency_key: idempotency_key.to_owned(),
            source: Some(UsageMode::OneironCloud),
            event_type: UsageEventType::Inference,
            occurred_at: Some(1_782_357_635),
            agent_id: Some("agent-a".to_owned()),
            model: Some("model-a".to_owned()),
            service: Some("inference".to_owned()),
            token_counts: UsageTokenCounts {
                input_tokens: 1_000,
                output_tokens: 500,
                cache_read_tokens: 2_000,
                cache_write_tokens: 1_000,
            },
            cost_rates: UsageCostRates {
                input_token_usd_per_million: 2.0,
                output_token_usd_per_million: 4.0,
                cache_read_token_usd_per_million: 0.5,
                cache_write_token_usd_per_million: 1.0,
            },
            service_cost_usd: 0.044,
            service_costs: Vec::new(),
        }
    }

    #[test]
    fn cost_calculator_includes_token_cache_and_service_costs() {
        let cost = cloud_event("cost-key").cost_input().calculate().unwrap();

        assert_eq!(cost.token_cost_usd, 0.004);
        assert_eq!(cost.cache_cost_usd, 0.002);
        assert_eq!(cost.service_cost_usd, 0.044);
        assert_eq!(cost.cost_usd, 0.05);
        assert_eq!(cost.credit_units, cost.cost_usd / CREDIT_UNIT_USD);
    }

    #[test]
    fn local_and_byo_telemetry_return_no_debit() {
        let (_dir, ledger) = test_ledger();
        let mut local = cloud_event("local-key");
        local.source = Some(UsageMode::Local);
        let mut byo = cloud_event("byo-key");
        byo.source = Some(UsageMode::Byo);

        let local_result = ledger
            .record_event(local, UsageMode::OneironCloud)
            .expect("local usage");
        let byo_result = ledger
            .record_event(byo, UsageMode::OneironCloud)
            .expect("byo usage");

        assert!(local_result.debit.is_none());
        assert!(byo_result.debit.is_none());
        assert!(ledger.tenant_rollup("tenant-a").unwrap().is_none());
    }

    #[test]
    fn oneiron_cloud_records_idempotent_debit_once() {
        let (_dir, ledger) = test_ledger();
        let first = ledger
            .record_event(cloud_event("same-key"), UsageMode::OneironCloud)
            .expect("first usage event");
        let second = ledger
            .record_event(cloud_event("same-key"), UsageMode::OneironCloud)
            .expect("replayed usage event");
        let rollup = ledger
            .tenant_rollup("tenant-a")
            .unwrap()
            .expect("tenant rollup");

        assert!(first.recorded);
        assert!(!first.replayed);
        assert!(!second.recorded);
        assert!(second.replayed);
        assert_eq!(rollup.counters.event_count, 1);
        assert_eq!(rollup.counters.cost_usd, 0.05);
        assert_eq!(rollup.counters.credit_units, 5.0);
    }

    #[test]
    fn rollups_include_agent_model_and_service_breakdowns() {
        let (_dir, ledger) = test_ledger();
        let mut second = cloud_event("second-key");
        second.agent_id = Some("agent-b".to_owned());
        second.model = Some("model-b".to_owned());
        second.service = Some("embedding".to_owned());

        ledger
            .record_event(cloud_event("first-key"), UsageMode::OneironCloud)
            .expect("first usage event");
        ledger
            .record_event(second, UsageMode::OneironCloud)
            .expect("second usage event");
        let vault_rollup = ledger
            .vault_rollup("tenant-a", "vault-a")
            .unwrap()
            .expect("vault rollup");

        assert_eq!(vault_rollup.counters.event_count, 2);
        assert_eq!(vault_rollup.agents["agent-a"].event_count, 1);
        assert_eq!(vault_rollup.agents["agent-b"].event_count, 1);
        assert_eq!(vault_rollup.models["model-a"].cost_usd, 0.05);
        assert_eq!(vault_rollup.models["model-b"].cost_usd, 0.05);
        assert_eq!(vault_rollup.services["inference"].credit_units, 5.0);
        assert_eq!(vault_rollup.services["embedding"].credit_units, 5.0);
    }
}
