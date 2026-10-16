//! Durable idempotent provider-list meters, aggregated only per owner and vault.
use super::{codec::*, keys::*, model::*};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
#[derive(Clone)]
pub struct UsageLedger {
    pub(super) vault: Arc<oneiron::Vault>,
}
impl UsageLedger {
    pub fn new(vault: Arc<oneiron::Vault>) -> Self {
        Self { vault }
    }
    pub fn record_event(
        &self,
        event: UsageEvent,
        source: UsageMode,
    ) -> Result<UsageRecordResult, UsageError> {
        event.validate()?;
        // A meter records facts for every payer. A source never turns a
        // quantity into a wallet debit, and an unknown price is not zero.
        let cost = event
            .cost_input()
            .map(|input| input.calculate())
            .transpose()?;
        let key = usage_event_key(&event.owner, &event.vault_id, &event.idempotency_key);
        let rollup_key = vault_rollup_key(&event.owner, &event.vault_id);
        self.vault
            .try_with_write_txn_grouped(|txn| -> Result<_, UsageError> {
                let mut rollup = self
                    .vault
                    .sync_state_get_in_write_txn(txn, &rollup_key)?
                    .map(|raw| decode_rollup(&raw))
                    .transpose()?;
                if rollup.is_none() {
                    self.vault.sync_state_visit_prefix_in_write_txn(
                        txn,
                        &usage_event_prefix(&event.owner, &event.vault_id),
                        |key, raw| {
                            merge_stored_event(&mut rollup, &event.owner, &event.vault_id, key, raw)
                        },
                    )?;
                    if let Some(rollup) = &rollup {
                        self.vault.sync_state_put_in_write_txn(
                            txn,
                            &rollup_key,
                            &encode_rollup(rollup)?,
                        )?;
                    }
                }
                if let Some(raw) = self.vault.sync_state_get_in_write_txn(txn, &key)? {
                    let stored = decode_entry(&raw)?;
                    if stored.event != event || stored.source != source {
                        return Err(UsageError::IdempotencyConflict);
                    }
                    return Ok(UsageRecordResult {
                        recorded: false,
                        replayed: true,
                        source: stored.source,
                        cost: stored.cost,
                        vault_rollup: rollup,
                    });
                }
                let mut rollup =
                    rollup.unwrap_or_else(|| UsageRollup::vault(&event.owner, &event.vault_id));
                rollup.add_event(&event, cost.as_ref())?;
                let stored = StoredUsageEvent {
                    event,
                    source,
                    cost: cost.clone(),
                    recorded_at: now_secs(),
                };
                self.vault
                    .sync_state_put_in_write_txn(txn, &key, &encode_entry(&stored)?)?;
                self.vault.sync_state_put_in_write_txn(
                    txn,
                    &rollup_key,
                    &encode_rollup(&rollup)?,
                )?;
                Ok(UsageRecordResult {
                    recorded: true,
                    replayed: false,
                    source,
                    cost,
                    vault_rollup: Some(rollup),
                })
            })
    }
    pub fn vault_rollup(
        &self,
        owner: &str,
        vault_id: &str,
    ) -> Result<Option<UsageRollup>, UsageError> {
        validate_dimension("owner", owner, MAX_DIMENSION_LEN)?;
        validate_dimension("vaultId", vault_id, MAX_DIMENSION_LEN)?;
        let key = vault_rollup_key(owner, vault_id);
        validate_key(&key)?;
        if let Some(raw) = self.vault.sync_state_get(&key)? {
            return decode_rollup(&raw).map(Some);
        }
        self.vault
            .try_with_write_txn_grouped(|txn| -> Result<_, UsageError> {
                let mut rollup = self
                    .vault
                    .sync_state_get_in_write_txn(txn, &key)?
                    .map(|raw| decode_rollup(&raw))
                    .transpose()?;
                if rollup.is_none() {
                    self.vault.sync_state_visit_prefix_in_write_txn(
                        txn,
                        &usage_event_prefix(owner, vault_id),
                        |key, raw| merge_stored_event(&mut rollup, owner, vault_id, key, raw),
                    )?;
                    if let Some(rollup) = &rollup {
                        self.vault.sync_state_put_in_write_txn(
                            txn,
                            &key,
                            &encode_rollup(rollup)?,
                        )?;
                    }
                }
                Ok(rollup)
            })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct StoredUsageEvent {
    pub event: UsageEvent,
    pub source: UsageMode,
    pub cost: Option<Money>,
    pub recorded_at: u64,
}

// Use the stamped money, never today's rate table, when rebuilding the derived view.
fn merge_stored_event(
    rollup: &mut Option<UsageRollup>,
    owner: &str,
    vault: &str,
    key: &str,
    raw: &[u8],
) -> Result<(), UsageError> {
    let stored = decode_entry(raw)?;
    stored.event.validate()?;
    if let Some(cost) = &stored.cost {
        cost.validate()?;
    }
    if stored.event.owner != owner
        || stored.event.vault_id != vault
        || usage_event_key(owner, vault, &stored.event.idempotency_key) != key
    {
        return Err(oneiron::Error::CorruptedIndex("usage event scope").into());
    }
    rollup
        .get_or_insert_with(|| UsageRollup::vault(owner, vault))
        .add_event(&stored.event, stored.cost.as_ref())
}
