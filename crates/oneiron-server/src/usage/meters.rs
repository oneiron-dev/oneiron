//! The four per-vault operational meters (ARCH-0011 `#meters`, FIX 7764):
//! what the host's own cost went to, recorded as facts. A meter row names a
//! quantity and never a price: nothing here prices, debits, refuses or
//! limits any work, and memory work is never charged. Each row is kept once
//! under its idempotency key, the spec's own (`msgrev:`, `embed:`, `rq:`,
//! `asset_gb_days:`), so a retry or a redelivery with the same payload never
//! counts twice and one with another payload is refused. The row's owner,
//! vault, metric and UTC-day rollup moves in the row's own write.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::codec::UsageError;
use super::keys::{
    MAX_DIMENSION_LEN, MAX_IDEMPOTENCY_KEY_LEN, meter_key, meter_rollup_key, now_secs,
    validate_dimension, validate_key, validate_optional_dimension,
};
use super::ledger::UsageLedger;
use super::model::UsageRollupStatus;

/// The length of one rollup period: a UTC day, the ledger's daily period.
pub const METER_PERIOD_SECS: u64 = 86_400;

/// One operational meter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperationalMetric {
    /// Tokens of an accepted MESSAGE revision.
    IngestTokens,
    /// Tokens embedded for a TURN, SUMMARY, CLAIM or ASSET_TEXT.
    EmbedTokens,
    /// Retrieval calls, split by the effort each asked for.
    RetrievalQueries,
    /// One day's average non-deleted blob bytes: a GB-day per 10^9.
    AssetGbDays,
}

impl OperationalMetric {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IngestTokens => "ingest_tokens",
            Self::EmbedTokens => "embed_tokens",
            Self::RetrievalQueries => "retrieval_queries",
            Self::AssetGbDays => "asset_gb_days",
        }
    }

    /// The unit a row's quantity counts in.
    pub fn unit(self) -> &'static str {
        match self {
            Self::IngestTokens | Self::EmbedTokens => "tokens",
            Self::RetrievalQueries => "queries",
            Self::AssetGbDays => "byte_days",
        }
    }

    /// The prefix the spec gives this metric's idempotency keys.
    fn key_prefix(self) -> &'static str {
        match self {
            Self::IngestTokens => "msgrev:",
            Self::EmbedTokens => "embed:",
            Self::RetrievalQueries => "rq:",
            Self::AssetGbDays => "asset_gb_days:",
        }
    }
}

/// The idempotency key of an ingest row: its accepted MESSAGE revision's.
pub fn ingest_key(revision: &str) -> String {
    format!("msgrev:{revision}")
}

/// The idempotency key of an embed row: the embedded entity's type, id and
/// source version.
pub fn embed_key(entity_type: &str, entity: &str, source_version: &str) -> String {
    format!("embed:{entity_type}:{entity}:{source_version}")
}

/// The idempotency key of a retrieval row: its request's id.
pub fn retrieval_key(request: &str) -> String {
    format!("rq:{request}")
}

/// The idempotency key of an owner-vault daily storage measurement:
/// `periodStart` is the start of its UTC day.
pub fn storage_key(owner: &str, vault_id: &str, period_start: u64) -> String {
    format!("asset_gb_days:{owner}:{vault_id}:{period_start}")
}

/// The start of the rollup period `at` falls in.
pub fn meter_period(at: u64) -> u64 {
    at - at % METER_PERIOD_SECS
}

/// One operational meter fact: who and which vault, the metric, the
/// quantity and the moment it happened, under its idempotency key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MeterRow {
    pub owner: String,
    pub vault_id: String,
    pub metric: OperationalMetric,
    pub idempotency_key: String,
    /// In the metric's unit ([`OperationalMetric::unit`]).
    pub quantity: u64,
    /// When it happened, in seconds; its rollup period is the UTC day this
    /// falls in.
    pub occurred_at: u64,
    /// What a row is split by within its metric's rollup: the effort a
    /// retrieval asked for, or the embedded entity's type; `None` otherwise.
    #[serde(default)]
    pub detail: Option<String>,
}

impl MeterRow {
    fn validate(&self) -> Result<(), UsageError> {
        validate_dimension("owner", &self.owner, MAX_DIMENSION_LEN)?;
        validate_dimension("vaultId", &self.vault_id, MAX_DIMENSION_LEN)?;
        validate_dimension(
            "idempotencyKey",
            &self.idempotency_key,
            MAX_IDEMPOTENCY_KEY_LEN,
        )?;
        validate_optional_dimension("detail", self.detail.as_deref())?;
        if !self.idempotency_key.starts_with(self.metric.key_prefix()) {
            return Err(UsageError::InvalidField {
                field: "idempotencyKey",
                message: "starts with the prefix the spec gives its metric's keys",
            });
        }
        validate_key(&meter_key(
            &self.owner,
            &self.vault_id,
            self.metric.as_str(),
            &self.idempotency_key,
        ))
    }
}

/// A meter row as stored: the row, and when it was recorded.
#[derive(Debug, Serialize, Deserialize)]
struct StoredMeterRow {
    row: MeterRow,
    recorded_at: u64,
}

/// A count of meter rows and the sum of their quantities.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MeterTotal {
    pub rows: u64,
    pub quantity: u64,
}

impl MeterTotal {
    fn added(&self, quantity: u64) -> Option<Self> {
        Some(Self {
            rows: self.rows.checked_add(1)?,
            quantity: self.quantity.checked_add(quantity)?,
        })
    }
}

/// One owner's vault's meter rows of one metric in one UTC day.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MeterRollup {
    pub owner: String,
    pub vault_id: String,
    pub metric: OperationalMetric,
    pub period_start: u64,
    /// [`UsageRollupStatus::Current`] or
    /// [`UsageRollupStatus::ArithmeticOverflow`]: a sum that would pass
    /// what it holds stops before the row that would carry it past, a floor
    /// and never the total.
    pub status: UsageRollupStatus,
    pub total: MeterTotal,
    /// The rows that name a detail, by it.
    pub by_detail: BTreeMap<String, MeterTotal>,
}

/// What recording one meter row did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MeterRecordResult {
    pub recorded: bool,
    pub replayed: bool,
    /// The row's period rollup as its write left it.
    pub rollup: MeterRollup,
}

impl UsageLedger {
    /// Records `row` once under its idempotency key, and adds it to its
    /// owner, vault, metric and day rollup in the same write. The same row
    /// again is a replay that changes nothing; another row under the same
    /// key is an idempotency conflict, and the first stands.
    pub fn record_meter(&self, row: MeterRow) -> Result<MeterRecordResult, UsageError> {
        row.validate()?;
        let metric = row.metric.as_str();
        let key = meter_key(&row.owner, &row.vault_id, metric, &row.idempotency_key);
        let period = meter_period(row.occurred_at);
        let rollup_key = meter_rollup_key(&row.owner, &row.vault_id, metric, period);
        validate_key(&rollup_key)?;
        self.vault
            .try_with_write_txn_grouped(|txn| -> Result<_, UsageError> {
                let rollup = self
                    .vault
                    .sync_state_get_in_write_txn(txn, &rollup_key)?
                    .map(|raw| rmp_serde::from_slice::<MeterRollup>(&raw))
                    .transpose()?;
                if let Some(raw) = self.vault.sync_state_get_in_write_txn(txn, &key)? {
                    let stored: StoredMeterRow = rmp_serde::from_slice(&raw)?;
                    if stored.row != row {
                        return Err(UsageError::IdempotencyConflict);
                    }
                    let rollup = rollup.ok_or(oneiron::Error::CorruptedIndex("meter rollup"))?;
                    return Ok(MeterRecordResult {
                        recorded: false,
                        replayed: true,
                        rollup,
                    });
                }
                let mut rollup = rollup.unwrap_or_else(|| MeterRollup {
                    owner: row.owner.clone(),
                    vault_id: row.vault_id.clone(),
                    metric: row.metric,
                    period_start: period,
                    status: UsageRollupStatus::Current,
                    total: MeterTotal::default(),
                    by_detail: BTreeMap::new(),
                });
                fold_meter(&mut rollup, &row);
                let stored = StoredMeterRow {
                    row,
                    recorded_at: now_secs(),
                };
                self.vault.sync_state_put_in_write_txn(
                    txn,
                    &key,
                    &rmp_serde::to_vec_named(&stored)?,
                )?;
                self.vault.sync_state_put_in_write_txn(
                    txn,
                    &rollup_key,
                    &rmp_serde::to_vec_named(&rollup)?,
                )?;
                Ok(MeterRecordResult {
                    recorded: true,
                    replayed: false,
                    rollup,
                })
            })
    }

    /// Records the owner-vault daily storage measurement for the UTC day
    /// starting at `period_start`: the day's average non-deleted blob bytes,
    /// under the spec's `asset_gb_days:<ownerId>:<vaultId>:<periodStart>`
    /// key, so each owner-vault day counts once and a later measurement of
    /// the same day never replaces the first.
    pub fn record_storage_day(
        &self,
        owner: &str,
        vault_id: &str,
        period_start: u64,
        average_bytes: u64,
    ) -> Result<MeterRecordResult, UsageError> {
        if !period_start.is_multiple_of(METER_PERIOD_SECS) {
            return Err(UsageError::InvalidField {
                field: "periodStart",
                message: "is the start of a UTC day",
            });
        }
        self.record_meter(MeterRow {
            owner: owner.to_owned(),
            vault_id: vault_id.to_owned(),
            metric: OperationalMetric::AssetGbDays,
            idempotency_key: storage_key(owner, vault_id, period_start),
            quantity: average_bytes,
            occurred_at: period_start,
            detail: None,
        })
    }

    /// The rollup of `metric` for the UTC day starting at `period_start`,
    /// `None` before its first row.
    pub fn meter_rollup(
        &self,
        owner: &str,
        vault_id: &str,
        metric: OperationalMetric,
        period_start: u64,
    ) -> Result<Option<MeterRollup>, UsageError> {
        Self::validate_scope(owner, vault_id)?;
        let key = meter_rollup_key(owner, vault_id, metric.as_str(), period_start);
        validate_key(&key)?;
        Ok(self
            .vault
            .sync_state_get(&key)?
            .map(|raw| rmp_serde::from_slice(&raw))
            .transpose()?)
    }
}

/// Adds `row` to `rollup`. Every sum is checked before any is kept: one that
/// would pass what it holds leaves the rollup as it was and marks it, and it
/// then takes no more rows.
fn fold_meter(rollup: &mut MeterRollup, row: &MeterRow) {
    if rollup.status != UsageRollupStatus::Current {
        return;
    }
    let detail = row.detail.as_ref().map(|detail| {
        let total = rollup.by_detail.get(detail).cloned().unwrap_or_default();
        (detail, total.added(row.quantity))
    });
    match (rollup.total.added(row.quantity), detail) {
        (Some(total), None) => rollup.total = total,
        (Some(total), Some((detail, Some(by_detail)))) => {
            rollup.total = total;
            rollup.by_detail.insert(detail.clone(), by_detail);
        }
        _ => {
            rollup.status = UsageRollupStatus::ArithmeticOverflow;
            tracing::warn!(
                metric = rollup.metric.as_str(),
                "an operational meter rollup sum would overflow; it counts the rows before that one"
            );
        }
    }
}
