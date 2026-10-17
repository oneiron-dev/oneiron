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
/// Most call keys a [`SeatUsage`] carries.
pub const SEAT_USAGE_REFS: usize = 64;
/// One seat's metered calls over a dated window, read from the stamped
/// events. An unpriced call leaves the sum a floor, never the bill: unknown is
/// never zero.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SeatUsage {
    pub calls: u64,
    /// Prompt tokens, cached reads and writes included.
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// The stamped prices summed, in 10^-9 units of `currency`.
    pub cost_amount: u64,
    pub currency: Option<String>,
    /// False when any call in the window has no price, or a price in another
    /// currency.
    pub complete: bool,
    /// Calls per model id.
    pub models: std::collections::BTreeMap<String, u64>,
    /// The vault's first metered call of any seat: a window that starts
    /// before it was not metered throughout.
    pub metered_since: Option<u64>,
    /// The newest calls' idempotency keys, at most [`SEAT_USAGE_REFS`].
    pub refs: Vec<String>,
}
impl UsageLedger {
    /// One seat's calls with `from <= at < until`, where `at` is when the call
    /// happened (its record time when the run gave none) and `seat` is the
    /// seat the run admitted it on.
    pub fn seat_usage(
        &self,
        owner: &str,
        vault_id: &str,
        seat: &str,
        from: u64,
        until: u64,
    ) -> Result<SeatUsage, UsageError> {
        validate_dimension("owner", owner, MAX_DIMENSION_LEN)?;
        validate_dimension("vaultId", vault_id, MAX_DIMENSION_LEN)?;
        let mut usage = SeatUsage {
            complete: true,
            ..SeatUsage::default()
        };
        let mut newest = std::collections::BinaryHeap::new();
        self.vault
            .try_with_write_txn_grouped(|txn| -> Result<_, UsageError> {
                self.vault.sync_state_visit_prefix_in_write_txn(
                    txn,
                    &usage_event_prefix(owner, vault_id),
                    |_, raw| -> Result<(), UsageError> {
                        let stored = decode_entry(raw)?;
                        let at = stored.event.occurred_at.unwrap_or(stored.recorded_at);
                        usage.metered_since =
                            Some(usage.metered_since.map_or(at, |since| since.min(at)));
                        if stored.event.role.as_deref() != Some(seat) || at < from || at >= until {
                            return Ok(());
                        }
                        let counts = &stored.event.token_counts;
                        usage.calls += 1;
                        usage.input_tokens = usage
                            .input_tokens
                            .saturating_add(counts.input_tokens)
                            .saturating_add(counts.cache_read_tokens)
                            .saturating_add(counts.cache_write_tokens);
                        usage.output_tokens =
                            usage.output_tokens.saturating_add(counts.output_tokens);
                        if let Some(model) = &stored.event.model {
                            *usage.models.entry(model.clone()).or_default() += 1;
                        }
                        match &stored.cost {
                            Some(cost)
                                if usage
                                    .currency
                                    .as_ref()
                                    .is_none_or(|currency| *currency == cost.currency) =>
                            {
                                usage.currency = Some(cost.currency.clone());
                                match usage.cost_amount.checked_add(cost.amount) {
                                    Some(sum) => usage.cost_amount = sum,
                                    None => usage.complete = false,
                                }
                            }
                            _ => usage.complete = false,
                        }
                        newest.push(std::cmp::Reverse((at, stored.event.idempotency_key)));
                        if newest.len() > SEAT_USAGE_REFS {
                            newest.pop();
                        }
                        Ok(())
                    },
                )
            })?;
        let mut newest = newest.into_vec();
        newest.sort_unstable();
        usage.refs = newest
            .into_iter()
            .map(|std::cmp::Reverse((_, key))| key)
            .collect();
        Ok(usage)
    }
}
