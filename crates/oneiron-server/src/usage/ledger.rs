//! Usage ledger: event recording, rollups, consumer usage reads, and top-ups.
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use super::allowance::{
    ConsumerAllowanceRecord, ConsumerAllowanceState, ConsumerAllowanceWarning, ConsumerTopUp,
    ConsumerTopUpRequest, ConsumerTopUpState, ConsumerUsageDetails, ConsumerUsageState,
};
use super::codec::{
    UsageError, decode_allowance, decode_entry, decode_rollup, decode_top_up, encode_allowance,
    encode_entry, encode_rollup, encode_top_up,
};
use super::keys::{
    MAX_DIMENSION_LEN, consumer_allowance_key, consumer_top_up_key, now_secs, tenant_rollup_key,
    usage_event_key, validate_consumer_usage_storage_keys, validate_dimension,
    validate_non_negative_finite, validate_positive_finite, vault_rollup_key,
};
use super::model::{
    CREDIT_UNIT_USD, UsageCost, UsageDebit, UsageEvent, UsageMode, UsageRecordResult, UsageRollup,
    normalize_money,
};
use super::telemetry::emit_usage_telemetry;

#[derive(Clone)]
pub struct UsageLedger {
    pub(super) vault: Arc<oneiron::Vault>,
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
        let source = configured_mode;
        let cost = event.cost_input().calculate()?;
        if !source.debits_usage() {
            emit_usage_telemetry(
                &event,
                source,
                &cost,
                &ConsumerAllowanceWarning::none(None),
                UsageTelemetryOutcome {
                    recorded: false,
                    replayed: false,
                    debited: false,
                },
            );
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
        let debit = UsageDebit {
            idempotency_key: event.idempotency_key.clone(),
            cost_usd: cost.cost_usd,
            credit_units: cost.credit_units,
        };
        let tenant_key = tenant_rollup_key(&event.tenant_id);
        let vault_key = vault_rollup_key(&event.tenant_id, &event.vault_id);
        let write_result =
            self.vault
                .try_with_write_txn(|wtxn| -> Result<LedgerWriteResult, UsageError> {
                    if let Some(raw) = self.vault.sync_state_get_in_write_txn(wtxn, &event_key)? {
                        return Ok(LedgerWriteResult::Replayed(decode_entry(&raw)?));
                    }

                    let mut tenant_rollup =
                        match self.vault.sync_state_get_in_write_txn(wtxn, &tenant_key)? {
                            Some(raw) => decode_rollup(&raw)?,
                            None => UsageRollup::tenant(event.tenant_id.clone()),
                        };
                    let mut vault_rollup = match self
                        .vault
                        .sync_state_get_in_write_txn(wtxn, &vault_key)?
                    {
                        Some(raw) => decode_rollup(&raw)?,
                        None => UsageRollup::vault(event.tenant_id.clone(), event.vault_id.clone()),
                    };
                    tenant_rollup.add_event(&event, &cost);
                    vault_rollup.add_event(&event, &cost);

                    let entry = StoredUsageEvent {
                        event: event.clone(),
                        source,
                        cost: cost.clone(),
                        debit: debit.clone(),
                        recorded_at: now_secs(),
                    };
                    let tenant_raw = encode_rollup(&tenant_rollup)?;
                    let vault_raw = encode_rollup(&vault_rollup)?;
                    let entry_raw = encode_entry(&entry)?;

                    self.vault
                        .sync_state_put_in_write_txn(wtxn, &tenant_key, &tenant_raw)?;
                    self.vault
                        .sync_state_put_in_write_txn(wtxn, &vault_key, &vault_raw)?;
                    self.vault
                        .sync_state_put_in_write_txn(wtxn, &event_key, &entry_raw)?;

                    Ok(LedgerWriteResult::Recorded {
                        tenant_rollup,
                        vault_rollup,
                    })
                })?;

        match write_result {
            LedgerWriteResult::Recorded {
                tenant_rollup,
                vault_rollup,
            } => {
                let warning = self.allowance_warning_for_tenant(
                    &event.tenant_id,
                    tenant_rollup.counters.credit_units,
                );
                emit_usage_telemetry(
                    &event,
                    source,
                    &cost,
                    &warning,
                    UsageTelemetryOutcome {
                        recorded: true,
                        replayed: false,
                        debited: true,
                    },
                );
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
            LedgerWriteResult::Replayed(entry) => self.replayed_result(entry),
        }
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

    pub fn consumer_usage(
        &self,
        tenant_id: &str,
        vault_id: Option<&str>,
        configured_mode: UsageMode,
    ) -> Result<ConsumerUsageState, UsageError> {
        validate_dimension("tenantId", tenant_id, MAX_DIMENSION_LEN)?;
        if let Some(vault_id) = vault_id {
            validate_dimension("vaultId", vault_id, MAX_DIMENSION_LEN)?;
        }
        validate_consumer_usage_storage_keys(tenant_id, vault_id)?;

        let _guard = self.lock.lock().map_err(|_| UsageError::LockPoisoned)?;
        self.consumer_usage_locked(tenant_id, vault_id, configured_mode)
    }

    pub fn consumer_usage_details(
        &self,
        tenant_id: &str,
        vault_id: Option<&str>,
        configured_mode: UsageMode,
    ) -> Result<ConsumerUsageDetails, UsageError> {
        validate_dimension("tenantId", tenant_id, MAX_DIMENSION_LEN)?;
        if let Some(vault_id) = vault_id {
            validate_dimension("vaultId", vault_id, MAX_DIMENSION_LEN)?;
        }
        validate_consumer_usage_storage_keys(tenant_id, vault_id)?;

        let _guard = self.lock.lock().map_err(|_| UsageError::LockPoisoned)?;
        let rollup = self.consumer_rollup_locked(tenant_id, vault_id)?;
        let allowance_used_credit_units = if vault_id.is_some() {
            self.tenant_used_credit_units_locked(tenant_id)?
        } else {
            rollup.counters.credit_units
        };
        let usage =
            self.consumer_usage_from_rollup(&rollup, configured_mode, allowance_used_credit_units)?;
        Ok(ConsumerUsageDetails {
            usage,
            agents: rollup.agents,
            models: rollup.models,
            services: rollup.services,
        })
    }

    pub fn top_up(
        &self,
        request: ConsumerTopUpRequest,
        configured_mode: UsageMode,
    ) -> Result<ConsumerTopUpState, UsageError> {
        request.validate()?;
        let credit_units = normalize_money(request.credit_units);
        validate_positive_finite("creditUnits", credit_units)?;
        let amount_usd = normalize_money(credit_units * CREDIT_UNIT_USD);
        let _guard = self.lock.lock().map_err(|_| UsageError::LockPoisoned)?;
        let top_up_key = consumer_top_up_key(&request.tenant_id, &request.idempotency_key);
        let allowance_key = consumer_allowance_key(&request.tenant_id);
        let write_result =
            self.vault
                .try_with_write_txn(|wtxn| -> Result<TopUpWriteResult, UsageError> {
                    if let Some(raw) = self.vault.sync_state_get_in_write_txn(wtxn, &top_up_key)? {
                        let top_up = decode_top_up(&raw)?;
                        if top_up.tenant_id != request.tenant_id
                            || top_up.idempotency_key != request.idempotency_key
                            || normalize_money(top_up.credit_units) != credit_units
                        {
                            return Err(UsageError::IdempotencyConflict {
                                tenant_id: request.tenant_id.clone(),
                                idempotency_key: request.idempotency_key.clone(),
                            });
                        }
                        return Ok(TopUpWriteResult::Replayed(top_up));
                    }

                    let recorded_at = now_secs();
                    let top_up = ConsumerTopUp {
                        tenant_id: request.tenant_id.clone(),
                        idempotency_key: request.idempotency_key.clone(),
                        credit_units,
                        amount_usd,
                        recorded_at,
                    };
                    let mut allowance = match self
                        .vault
                        .sync_state_get_in_write_txn(wtxn, &allowance_key)?
                    {
                        Some(raw) => decode_allowance(&raw)?,
                        None => ConsumerAllowanceRecord {
                            credit_units: 0.0,
                            updated_at: None,
                        },
                    };
                    let previous_credit_units = normalize_money(allowance.credit_units);
                    validate_non_negative_finite("creditUnits", previous_credit_units)?;
                    let updated_credit_units =
                        normalize_money(previous_credit_units + top_up.credit_units);
                    validate_positive_finite("creditUnits", updated_credit_units)?;
                    if updated_credit_units <= previous_credit_units {
                        return Err(UsageError::InvalidField {
                            field: "creditUnits",
                            message: "must increase allowance balance",
                        });
                    }
                    allowance.credit_units = updated_credit_units;
                    allowance.updated_at = Some(recorded_at);

                    self.vault.sync_state_put_in_write_txn(
                        wtxn,
                        &allowance_key,
                        &encode_allowance(&allowance)?,
                    )?;
                    self.vault.sync_state_put_in_write_txn(
                        wtxn,
                        &top_up_key,
                        &encode_top_up(&top_up)?,
                    )?;

                    Ok(TopUpWriteResult::Recorded(top_up))
                })?;

        match write_result {
            TopUpWriteResult::Recorded(top_up) => {
                let usage = self.consumer_usage_locked(&top_up.tenant_id, None, configured_mode)?;
                Ok(ConsumerTopUpState {
                    recorded: true,
                    replayed: false,
                    top_up,
                    usage,
                })
            }
            TopUpWriteResult::Replayed(top_up) => {
                let usage = self.consumer_usage_locked(&top_up.tenant_id, None, configured_mode)?;
                Ok(ConsumerTopUpState {
                    recorded: false,
                    replayed: true,
                    top_up,
                    usage,
                })
            }
        }
    }

    fn replayed_result(&self, entry: StoredUsageEvent) -> Result<UsageRecordResult, UsageError> {
        let tenant_rollup = self.get_rollup(&tenant_rollup_key(&entry.event.tenant_id))?;
        let vault_rollup = self.get_rollup(&vault_rollup_key(
            &entry.event.tenant_id,
            &entry.event.vault_id,
        ))?;
        let warning = self.allowance_warning_for_tenant(
            &entry.event.tenant_id,
            tenant_rollup
                .as_ref()
                .map_or(0.0, |rollup| rollup.counters.credit_units),
        );
        emit_usage_telemetry(
            &entry.event,
            entry.source,
            &entry.cost,
            &warning,
            UsageTelemetryOutcome {
                recorded: false,
                replayed: true,
                debited: true,
            },
        );
        Ok(UsageRecordResult {
            recorded: false,
            replayed: true,
            source: entry.source,
            cost: entry.cost,
            debit: Some(entry.debit),
            tenant_rollup,
            vault_rollup,
        })
    }

    fn get_rollup(&self, key: &str) -> Result<Option<UsageRollup>, UsageError> {
        let Some(raw) = self.vault.sync_state_get(key)? else {
            return Ok(None);
        };
        decode_rollup(&raw).map(Some)
    }

    fn consumer_usage_locked(
        &self,
        tenant_id: &str,
        vault_id: Option<&str>,
        configured_mode: UsageMode,
    ) -> Result<ConsumerUsageState, UsageError> {
        let rollup = self.consumer_rollup_locked(tenant_id, vault_id)?;
        let allowance_used_credit_units = if vault_id.is_some() {
            self.tenant_used_credit_units_locked(tenant_id)?
        } else {
            rollup.counters.credit_units
        };
        self.consumer_usage_from_rollup(&rollup, configured_mode, allowance_used_credit_units)
    }

    fn consumer_usage_from_rollup(
        &self,
        rollup: &UsageRollup,
        configured_mode: UsageMode,
        allowance_used_credit_units: f64,
    ) -> Result<ConsumerUsageState, UsageError> {
        let allowance = self.consumer_allowance(&rollup.tenant_id)?;
        let remaining_credit_units =
            normalize_money(allowance.credit_units - allowance_used_credit_units).max(0.0);
        Ok(ConsumerUsageState {
            tenant_id: rollup.tenant_id.clone(),
            vault_id: rollup.vault_id.clone(),
            mode: configured_mode,
            counters: rollup.counters.clone(),
            allowance: ConsumerAllowanceState {
                allowance_credit_units: allowance.credit_units,
                used_credit_units: allowance_used_credit_units,
                remaining_credit_units,
                updated_at: allowance.updated_at,
                warning: ConsumerAllowanceWarning::for_usage(
                    allowance_used_credit_units,
                    allowance.credit_units,
                ),
            },
        })
    }

    fn consumer_rollup_locked(
        &self,
        tenant_id: &str,
        vault_id: Option<&str>,
    ) -> Result<UsageRollup, UsageError> {
        if let Some(vault_id) = vault_id {
            return self
                .get_rollup(&vault_rollup_key(tenant_id, vault_id))
                .map(|rollup| rollup.unwrap_or_else(|| UsageRollup::vault(tenant_id, vault_id)));
        }

        self.get_rollup(&tenant_rollup_key(tenant_id))
            .map(|rollup| rollup.unwrap_or_else(|| UsageRollup::tenant(tenant_id)))
    }

    fn tenant_used_credit_units_locked(&self, tenant_id: &str) -> Result<f64, UsageError> {
        self.get_rollup(&tenant_rollup_key(tenant_id))
            .map(|rollup| rollup.map_or(0.0, |rollup| rollup.counters.credit_units))
    }

    pub(super) fn consumer_allowance(
        &self,
        tenant_id: &str,
    ) -> Result<ConsumerAllowanceRecord, UsageError> {
        let Some(raw) = self
            .vault
            .sync_state_get(&consumer_allowance_key(tenant_id))?
        else {
            return Ok(ConsumerAllowanceRecord {
                credit_units: 0.0,
                updated_at: None,
            });
        };
        decode_allowance(&raw)
    }

    fn allowance_warning_for_tenant(
        &self,
        tenant_id: &str,
        used_credit_units: f64,
    ) -> ConsumerAllowanceWarning {
        match self.consumer_allowance(tenant_id) {
            Ok(allowance) => {
                ConsumerAllowanceWarning::for_usage(used_credit_units, allowance.credit_units)
            }
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    tenant_id = %tenant_id,
                    "usage telemetry allowance lookup failed"
                );
                ConsumerAllowanceWarning::none(None)
            }
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct UsageTelemetryOutcome {
    pub(super) recorded: bool,
    pub(super) replayed: bool,
    pub(super) debited: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct StoredUsageEvent {
    pub(super) event: UsageEvent,
    pub(super) source: UsageMode,
    pub(super) cost: UsageCost,
    pub(super) debit: UsageDebit,
    pub(super) recorded_at: u64,
}

enum LedgerWriteResult {
    Recorded {
        tenant_rollup: UsageRollup,
        vault_rollup: UsageRollup,
    },
    Replayed(StoredUsageEvent),
}

enum TopUpWriteResult {
    Recorded(ConsumerTopUp),
    Replayed(ConsumerTopUp),
}
