//! Durable idempotent provider-list meters, aggregated only per owner and vault.
use super::{codec::*, keys::*, model::*};
use oneiron::EntityId;
use oneiron::agent_dispatch::budget_doors::{RunRungSettlement, UsageEventOrigin};
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
    /// Records `event` once under its idempotency key, billed as `source`
    /// and written by `origin`, the engine or a usage post. A posted event
    /// names no row its facts were read from: its rows stay unknown.
    pub fn record_event(
        &self,
        event: UsageEvent,
        source: UsageMode,
        origin: UsageEventOrigin,
    ) -> Result<UsageRecordResult, UsageError> {
        self.record_event_sourced(event, source, origin, None)
    }

    /// [`Self::record_event`] for the engine's own settlement, with the rows
    /// the call's facts were read from as its admission froze them: its
    /// input's and its list price's (FIX 5760). `None` is unknown. A replay
    /// keeps the first write's rows.
    pub(crate) fn record_event_sourced(
        &self,
        event: UsageEvent,
        source: UsageMode,
        origin: UsageEventOrigin,
        source_rows: Option<Vec<EntityId>>,
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
                    // The first write's origin stands: a replay never
                    // relabels it, and origin never makes one conflict.
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
                    origin,
                    cost: cost.clone(),
                    recorded_at: now_secs(),
                    source_rows,
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
    /// Settled physical calls of one run, from their stamped durable events.
    pub fn run_settlements(
        &self,
        owner: &str,
        vault_id: &str,
        run: &str,
    ) -> Result<Vec<RunRungSettlement>, UsageError> {
        validate_dimension("owner", owner, MAX_DIMENSION_LEN)?;
        validate_dimension("vaultId", vault_id, MAX_DIMENSION_LEN)?;
        validate_dimension("run", run, MAX_DIMENSION_LEN)?;
        let mut rows = Vec::new();
        self.vault
            .try_with_write_txn_grouped(|txn| -> Result<(), UsageError> {
                self.vault.sync_state_visit_prefix_in_write_txn(
                    txn,
                    &usage_event_prefix(owner, vault_id),
                    |key, raw| -> Result<(), UsageError> {
                        let stored = decode_entry(raw)?;
                        let event = &stored.event;
                        if event.owner != owner
                            || event.vault_id != vault_id
                            || usage_event_key(owner, vault_id, &event.idempotency_key) != key
                        {
                            return Err(oneiron::Error::CorruptedIndex("usage event scope").into());
                        }
                        let Some(call) = event.run.as_ref().filter(|call| call.run == run) else {
                            return Ok(());
                        };
                        rows.push(settlement(&stored, call));
                        Ok(())
                    },
                )
            })?;
        rows.sort_by(|a, b| (&a.instance, &a.lease).cmp(&(&b.instance, &b.lease)));
        Ok(rows)
    }

    /// The settled physical calls of one free-time cycle (FIX 4453), from
    /// their stamped durable events, oldest first: every call stamped with
    /// `agent`'s `cycle`, each retry, fallback and late settlement included,
    /// whether the engine stamped its run before it began or a poster
    /// stamped the event. Each entry's `source` says which (FIX 5724); both
    /// count alike. A call no cycle stamp names never matches. A stored
    /// event that does not decode leaves the read incomplete and is never
    /// read as zero spend.
    pub fn cycle_settlements(
        &self,
        owner: &str,
        vault_id: &str,
        agent: &str,
        cycle: &str,
    ) -> Result<CycleSettlements, UsageError> {
        validate_dimension("owner", owner, MAX_DIMENSION_LEN)?;
        validate_dimension("vaultId", vault_id, MAX_DIMENSION_LEN)?;
        validate_dimension("agent", agent, MAX_DIMENSION_LEN)?;
        validate_dimension("cycle", cycle, MAX_DIMENSION_LEN)?;
        let mut read = CycleSettlements {
            settlements: Vec::new(),
            complete: true,
        };
        self.vault
            .try_with_write_txn_grouped(|txn| -> Result<(), UsageError> {
                self.vault.sync_state_visit_prefix_in_write_txn(
                    txn,
                    &usage_event_prefix(owner, vault_id),
                    |key, raw| -> Result<(), UsageError> {
                        let Ok(stored) = decode_entry(raw) else {
                            read.complete = false;
                            return Ok(());
                        };
                        let event = &stored.event;
                        if event.owner != owner
                            || event.vault_id != vault_id
                            || usage_event_key(owner, vault_id, &event.idempotency_key) != key
                        {
                            return Err(oneiron::Error::CorruptedIndex("usage event scope").into());
                        }
                        if event.agent_id.as_deref() != Some(agent) {
                            return Ok(());
                        }
                        let Some(call) = event
                            .run
                            .as_ref()
                            .filter(|call| call.cycle.as_deref() == Some(cycle))
                        else {
                            return Ok(());
                        };
                        read.settlements.push(settlement(&stored, call));
                        Ok(())
                    },
                )
            })?;
        read.settlements.sort_by(|a, b| {
            (a.occurred_at, &a.instance, &a.lease).cmp(&(b.occurred_at, &b.instance, &b.lease))
        });
        Ok(read)
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
/// One free-time cycle's settled calls, as [`UsageLedger::cycle_settlements`]
/// read them.
#[derive(Clone, Debug)]
pub struct CycleSettlements {
    pub settlements: Vec<RunRungSettlement>,
    /// False when a stored event did not decode: the records shown are then
    /// some of the spend, never all of it.
    pub complete: bool,
}

/// One stored call's settlement, with the safe spend dimensions its record
/// names (run, label, agent, cycle, item and spend scope) and the path that
/// first wrote it.
fn settlement(stored: &StoredUsageEvent, call: &UsageRun) -> RunRungSettlement {
    let event = &stored.event;
    RunRungSettlement {
        instance: call.instance.clone(),
        lease: call.lease.clone(),
        run: call.run.clone(),
        revision: call.revision,
        model: event.model.clone(),
        offer: call.offer.clone(),
        route: call.route.clone(),
        purpose: call.purpose.clone(),
        source: stored.origin,
        agent: event.agent_id.clone(),
        cycle: call.cycle.clone(),
        item: call.item.clone(),
        spend_scope: call.spend_scope.clone(),
        reserved_units: call.reserved_units,
        settled_units: call.settled_units,
        unit: call.unit.clone(),
        usage_reported: call.usage_reported,
        settlement_refused: call.settlement_refused,
        occurred_at: event.occurred_at.unwrap_or(stored.recorded_at),
        cost_amount: stored.cost.as_ref().map(|cost| cost.amount),
        currency: stored.cost.as_ref().map(|cost| cost.currency.clone()),
        price_table_snapshot: stored
            .cost
            .as_ref()
            .map(|cost| cost.price_table_snapshot.clone()),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct StoredUsageEvent {
    pub event: UsageEvent,
    pub source: UsageMode,
    /// The path that first wrote the event; a replay never relabels it.
    pub origin: UsageEventOrigin,
    pub cost: Option<Money>,
    pub recorded_at: u64,
    /// The rows the call's facts were read from, as the engine's settlement
    /// froze them (FIX 5760); `None`, unknown, on a posted event and on an
    /// older record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_rows: Option<Vec<EntityId>>,
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
/// One seat's metered calls over a dated window, read from the stamped
/// events. An unpriced call leaves the sum a floor, never the bill: unknown is
/// never zero.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SeatUsage {
    /// The window's calls (on the one model a read asks for), and every
    /// stored event that does not decode.
    pub calls: u64,
    /// Prompt tokens, cached reads and writes included.
    pub input_tokens: u64,
    /// The cached reads among `input_tokens`.
    pub cache_read_tokens: u64,
    /// The cached writes among `input_tokens`.
    pub cache_write_tokens: u64,
    pub output_tokens: u64,
    /// The stamped prices summed, in 10^-9 units of `currency`.
    pub cost_amount: u64,
    pub currency: Option<String>,
    /// False when any call in the window has no price, a price in another
    /// currency, or one the sum cannot hold: exactly when
    /// [`SeatUsage::gap_calls`] is above zero.
    pub complete: bool,
    /// The unpriced calls whose record says they measured no tokens.
    pub no_usage: u64,
    /// The unpriced calls whose record says no list price was frozen on
    /// them at admission.
    pub unpriced_model: u64,
    /// The unpriced calls whose record says their frozen rates quote no rate
    /// for a cache dimension they measured.
    pub unpriced_cache: UnpricedCache,
    /// The calls priced in a currency other than `currency`, the first
    /// priced call's; left out of `cost_amount`.
    pub mixed_currency: u64,
    /// The calls whose price would carry `cost_amount` past what it holds;
    /// left out of it.
    pub sum_overflow: u64,
    /// The unpriced calls whose record names no reason: an older record, a
    /// posted one that gave none, or one that does not decode.
    pub unclassified: u64,
    /// The stored events that do not decode, each also counted in `calls`
    /// and `unclassified`: when, on which seat and on which model one ran is
    /// unknown, so every read counts it.
    pub undecodable: u64,
    /// The seat's window calls a read for one model left out: those on
    /// another model, or naming none.
    pub counted_out: u64,
    /// Calls per model id.
    pub models: std::collections::BTreeMap<String, u64>,
    /// The vault's first metered call of any seat: a window that starts
    /// before it was not metered throughout.
    pub metered_since: Option<u64>,
    /// Every window call's idempotency key, the counted-out calls' too,
    /// newest first.
    pub refs: Vec<String>,
    /// The rows the window's calls, the counted-out ones too, were read
    /// from, as each call's settlement froze them (FIX 5760); `None` when
    /// any one's are unknown or a stored event does not decode. Another
    /// seat's call adds only its time to `metered_since`, which no row of
    /// its makes.
    pub source_rows: Option<Vec<EntityId>>,
}
impl SeatUsage {
    /// The window's calls not priced and summed in `currency`, each counted
    /// once under one kind: zero exactly when `complete`.
    pub fn gap_calls(&self) -> u64 {
        [
            self.no_usage,
            self.unpriced_model,
            self.unpriced_cache.calls,
            self.mixed_currency,
            self.sum_overflow,
            self.unclassified,
        ]
        .into_iter()
        .fold(0, u64::saturating_add)
    }
}
/// A window's calls left unpriced only because the rates frozen on each
/// quote no rate for a cache dimension it measured.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnpricedCache {
    /// Such calls, each counted once.
    pub calls: u64,
    /// Those with cached reads and no quoted cache-read rate.
    pub cache_read: u64,
    /// Those with cached writes and no quoted cache-write rate.
    pub cache_write: u64,
}
impl UnpricedCache {
    fn add(&mut self, dimensions: &[CacheDimension]) {
        self.calls = self.calls.saturating_add(1);
        for dimension in dimensions {
            let calls = match dimension {
                CacheDimension::CacheRead => &mut self.cache_read,
                CacheDimension::CacheWrite => &mut self.cache_write,
            };
            *calls = calls.saturating_add(1);
        }
    }
}
impl UsageLedger {
    /// One seat's calls with `from <= at < until`, where `at` is when the call
    /// happened (its record time when the run gave none) and `seat` is the
    /// seat the run admitted it on. With a `model`, only its calls are read:
    /// the seat's others are counted out.
    pub fn seat_usage(
        &self,
        owner: &str,
        vault_id: &str,
        seat: &str,
        model: Option<&str>,
        from: u64,
        until: u64,
    ) -> Result<SeatUsage, UsageError> {
        validate_dimension("owner", owner, MAX_DIMENSION_LEN)?;
        validate_dimension("vaultId", vault_id, MAX_DIMENSION_LEN)?;
        let mut usage = SeatUsage::default();
        let mut refs = Vec::new();
        // `None` once one counted call's rows are unknown.
        let mut sources: Option<Vec<EntityId>> = Some(Vec::new());
        self.vault
            .try_with_write_txn_grouped(|txn| -> Result<_, UsageError> {
                self.vault.sync_state_visit_prefix_in_write_txn(
                    txn,
                    &usage_event_prefix(owner, vault_id),
                    |_, raw| -> Result<(), UsageError> {
                        // A stored event that does not decode is counted as a
                        // call with no price and no reason, never read as zero
                        // spend, and never fails the whole read.
                        let Ok(stored) = decode_entry(raw) else {
                            usage.calls += 1;
                            usage.unclassified += 1;
                            usage.undecodable += 1;
                            sources = None;
                            return Ok(());
                        };
                        let at = stored.event.occurred_at.unwrap_or(stored.recorded_at);
                        usage.metered_since =
                            Some(usage.metered_since.map_or(at, |since| since.min(at)));
                        if stored.event.role.as_deref() != Some(seat) || at < from || at >= until {
                            return Ok(());
                        }
                        match stored.source_rows.as_deref() {
                            Some(read) => {
                                if let Some(rows) = &mut sources {
                                    rows.extend_from_slice(read);
                                }
                            }
                            None => sources = None,
                        }
                        if model.is_some_and(|model| stored.event.model.as_deref() != Some(model)) {
                            usage.counted_out += 1;
                            refs.push(std::cmp::Reverse((at, stored.event.idempotency_key)));
                            return Ok(());
                        }
                        let counts = &stored.event.token_counts;
                        usage.calls += 1;
                        usage.input_tokens = usage
                            .input_tokens
                            .saturating_add(counts.input_tokens)
                            .saturating_add(counts.cache_read_tokens)
                            .saturating_add(counts.cache_write_tokens);
                        usage.cache_read_tokens = usage
                            .cache_read_tokens
                            .saturating_add(counts.cache_read_tokens);
                        usage.cache_write_tokens = usage
                            .cache_write_tokens
                            .saturating_add(counts.cache_write_tokens);
                        usage.output_tokens =
                            usage.output_tokens.saturating_add(counts.output_tokens);
                        if let Some(model) = &stored.event.model {
                            *usage.models.entry(model.clone()).or_default() += 1;
                        }
                        // Priced and summed in the window's currency, or
                        // counted once under why not: an unpriced call by the
                        // reason its settlement recorded, an older record that
                        // names none apart.
                        match (&stored.cost, &stored.event.unpriced) {
                            (Some(cost), _)
                                if usage
                                    .currency
                                    .as_ref()
                                    .is_none_or(|currency| *currency == cost.currency) =>
                            {
                                usage.currency = Some(cost.currency.clone());
                                match usage.cost_amount.checked_add(cost.amount) {
                                    Some(sum) => usage.cost_amount = sum,
                                    None => usage.sum_overflow += 1,
                                }
                            }
                            (Some(_), _) => usage.mixed_currency += 1,
                            (None, Some(UnpricedReason::NoUsage)) => usage.no_usage += 1,
                            (None, Some(UnpricedReason::UnpricedModel)) => {
                                usage.unpriced_model += 1;
                            }
                            (None, Some(UnpricedReason::UnquotedCache { dimensions })) => {
                                usage.unpriced_cache.add(dimensions);
                            }
                            (None, None) => usage.unclassified += 1,
                        }
                        refs.push(std::cmp::Reverse((at, stored.event.idempotency_key)));
                        Ok(())
                    },
                )
            })?;
        if usage.undecodable > 0 {
            tracing::warn!(
                undecodable = usage.undecodable,
                "stored usage events that do not decode were counted as unpriced calls"
            );
        }
        usage.complete = usage.gap_calls() == 0;
        usage.source_rows = oneiron::skill_optimize::union_source_rows([sources]);
        refs.sort_unstable();
        usage.refs = refs
            .into_iter()
            .map(|std::cmp::Reverse((_, key))| key)
            .collect();
        Ok(usage)
    }
}
