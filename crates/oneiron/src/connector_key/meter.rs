//! Effector budget windows, usage rows and the budget charge facade.
//! Entry: `EffectorBudgetRead`.
//! Windows and usage are defined here; charging lives in `charge`.

use std::io::Cursor;

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::{BudgetSignalDeliveryChannel, BudgetSteeringSignal, BudgetThreshold};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::store::Store;

use super::lifecycle::derived_key_catalog_in_txn;
use super::record::{
    CalendarPeriod, ConnectorKeyRecord, ConnectorKeyStatus, EffectorBudget,
    EffectorBudgetDimension, EffectorBudgetOnExhaust, EffectorBudgetWindow,
};
use super::txn::suspend_connector_key_in_txn;

mod charge;
mod rate_window;
mod reservation;
mod row;
mod spend_reserve;
pub(crate) use self::charge::{
    charge_effector_budgets, charge_effector_budgets_pooled, preflight_effector_budgets_pooled,
    shares_budget_pool,
};
pub(crate) use self::rate_window::{BudgetBlock, budget_block_pooled};
pub use self::reservation::EffectorBudgetDebit;
pub(crate) use self::reservation::release_effector_debits_in_txn;
pub(crate) use self::row::EFFECTOR_BUDGET_ROW_KEY_LEN;
pub(crate) use self::row::budget_exhausted_reason;
use self::row::row_ordinal;
pub use self::row::{
    EffectorBudgetLadderEvent, EffectorBudgetLocation, EffectorBudgetRowId, EffectorBudgetRowSource,
};
pub(crate) use self::spend_reserve::{
    SpendReserve, reconcile_connector_spend_in_txn, reserve_connector_spend_in_txn,
};

/// vault_meta usage rows: key id (16 bytes) ++ row source tag u8 ++ row
/// ordinal u64 BE (`EffectorBudgetRowId::usage_key`) -> canonical msgpack
/// `{window_start, entries, fired}`.
pub(super) const USAGE: SideTable<
    (EntityId, [u8; EFFECTOR_BUDGET_ROW_KEY_LEN]),
    ConnectorKeyUsage,
    Raw,
> = SideTable::new(&side_table::CONNECTOR_KEY_USAGE);

pub(super) const SECONDS_PER_DAY: u64 = 86_400;

/// Template id for the effector-meter ~80% wrap-up notice (GOV-02, ONE-1418).
/// The LADDER and the delivery CHANNEL are the ARCHPASS-A3 shared vocabulary
/// from `llm::budget`; only the message text is meter-specific.
pub const EFFECTOR_BUDGET_PLAN_PROMPT_TEMPLATE_ID: &str = "effector_budget.plan.80";
/// Template id for the effector-meter 95% LAND / graceful-wrap signal.
pub const EFFECTOR_BUDGET_LAND_PROMPT_TEMPLATE_ID: &str = "effector_budget.land.95";
/// Steering message injected at the 80% effector-budget threshold.
pub const EFFECTOR_BUDGET_PLAN_PROMPT_TEMPLATE: &str = "\
Effector budget is at or above 80%. Prioritize the sends that still matter, \
defer the rest, and plan to finish within the remaining allowance.";
/// Steering message injected at the 95% effector-budget threshold.
pub const EFFECTOR_BUDGET_LAND_PROMPT_TEMPLATE: &str = "\
Effector budget is at or above 95%. Enter LAND: start no new outreach, finish \
or checkpoint in-flight sends, and treat the remaining allowance as a \
graceful-wrap window before the hard cut.";

/// Mirror of `llm::budget::steering_signal` for the effector meter: same
/// ladder, same one delivery channel, meter-specific texts. `Silent50`
/// carries no steering (same as the LLM meter).
pub(super) fn effector_steering_signal(threshold: BudgetThreshold) -> Option<BudgetSteeringSignal> {
    let (template_id, message) = match threshold {
        BudgetThreshold::Silent50 => return None,
        BudgetThreshold::Plan80 => (
            EFFECTOR_BUDGET_PLAN_PROMPT_TEMPLATE_ID,
            EFFECTOR_BUDGET_PLAN_PROMPT_TEMPLATE,
        ),
        BudgetThreshold::Land95 => (
            EFFECTOR_BUDGET_LAND_PROMPT_TEMPLATE_ID,
            EFFECTOR_BUDGET_LAND_PROMPT_TEMPLATE,
        ),
    };
    Some(BudgetSteeringSignal {
        threshold,
        channel: BudgetSignalDeliveryChannel::SteeringQueueNextTurn,
        template_id: template_id.to_owned(),
        message: message.to_owned(),
    })
}

/// Pinned usage-row `fired` names (serde snake_case of `BudgetThreshold`).
const fn budget_threshold_fired_name(threshold: BudgetThreshold) -> &'static str {
    match threshold {
        BudgetThreshold::Silent50 => "silent50",
        BudgetThreshold::Plan80 => "plan80",
        BudgetThreshold::Land95 => "land95",
    }
}

// --- Window math ------------------------------------------------------------

/// Returns the UTC bucket start for a calendar window at `now` (Unix seconds).
///
/// Day: midnight UTC. Week: Monday-start UTC (saturating — for `now` before
/// 1970-01-05 the Monday-start would be negative, so the bucket clamps to the
/// epoch instead of underflowing u64). Month: first-of-month 00:00:00 UTC via
/// the Hinnant civil-date algorithm.
#[must_use]
pub(super) fn calendar_window_start(period: CalendarPeriod, now: u64) -> u64 {
    match period {
        CalendarPeriod::Day => now - now % SECONDS_PER_DAY,
        CalendarPeriod::Week => {
            let days = now / SECONDS_PER_DAY;
            days.saturating_sub((days + 3) % 7) * SECONDS_PER_DAY
        }
        CalendarPeriod::Month => {
            let days = i64::try_from(now / SECONDS_PER_DAY).unwrap_or(i64::MAX);
            let (year, month, _day) = civil_from_days(days);
            let month_start_days = days_from_civil(year, month, 1);
            u64::try_from(month_start_days).unwrap_or(0) * SECONDS_PER_DAY
        }
    }
}

/// Hinnant `civil_from_days`: days since 1970-01-01 → (year, month, day).
const fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Hinnant `days_from_civil`: (year, month, day) → days since 1970-01-01.
const fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64; // [0, 11]
    let doy = (153 * mp + 2) / 5 + d as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

// --- Usage rows -------------------------------------------------------------

/// Live usage state for one (key, budget row) pair, stored in `vault_meta`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct ConnectorKeyUsage {
    /// Current calendar bucket start; 0 for rolling windows.
    pub(crate) window_start: u64,
    /// `(ts, amount)` debit log, pruned on every touch.
    pub(crate) entries: Vec<(u64, u64)>,
    /// Ladder thresholds fired this window (GOV-01 writes it empty; GOV-02
    /// populates it): `"silent50" | "plan80" | "land95"`.
    pub(crate) fired: Vec<String>,
}

impl ConnectorKeyUsage {
    pub(crate) fn used(&self) -> u64 {
        self.entries
            .iter()
            .fold(0_u64, |sum, (_, amount)| sum.saturating_add(*amount))
    }

    /// Prunes entries to window liveness at `now`. Calendar rollover resets
    /// `entries` and `fired` (fresh bucket ⇒ fresh ladder). Rolling windows
    /// have no discrete rollover, so the ladder re-arms per the M5a rule
    /// (resolved 2026-07-10): on each touch, drop `fired` entries whose
    /// threshold percent exceeds the current `percent_used` — full expiry
    /// re-arms everything, partial expiry re-arms exactly the thresholds no
    /// longer satisfied.
    pub(crate) fn touch(&mut self, window: &EffectorBudgetWindow, limit: u64, now: u64) {
        match window {
            EffectorBudgetWindow::Rolling { duration_s } => {
                self.window_start = 0;
                self.entries
                    .retain(|(ts, _)| ts.saturating_add(*duration_s) > now);
                let percent = percent_used(self.used(), limit);
                self.fired.retain(|name| {
                    parse_fired_threshold(name)
                        .is_none_or(|threshold| threshold.percent() <= percent)
                });
            }
            EffectorBudgetWindow::Calendar { period, .. } => {
                let bucket = calendar_window_start(*period, now);
                if self.window_start != bucket {
                    self.window_start = bucket;
                    self.entries.clear();
                    self.fired.clear();
                } else {
                    self.entries.retain(|(ts, _)| *ts >= bucket);
                }
            }
        }
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let value = Value::Map(vec![
            (Value::from("window_start"), Value::from(self.window_start)),
            (
                Value::from("entries"),
                Value::Array(
                    self.entries
                        .iter()
                        .map(|(ts, amount)| {
                            Value::Array(vec![Value::from(*ts), Value::from(*amount)])
                        })
                        .collect(),
                ),
            ),
            (
                Value::from("fired"),
                Value::Array(
                    self.fired
                        .iter()
                        .map(|name| Value::from(name.clone()))
                        .collect(),
                ),
            ),
        ]);
        let mut out = Vec::new();
        rmpv::encode::write_value(&mut out, &value)
            .map_err(|_| Error::InvariantViolation("connector key usage encode failed"))?;
        Ok(out)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let corrupted = || Error::CorruptedIndex("connector key usage row");
        let mut cursor = Cursor::new(bytes);
        let value = rmpv::decode::read_value(&mut cursor).map_err(|_| corrupted())?;
        if cursor.position() != bytes.len() as u64 {
            return Err(corrupted());
        }
        let Value::Map(entries) = value else {
            return Err(corrupted());
        };
        let field = |key: &str| {
            entries
                .iter()
                .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
                .ok_or_else(corrupted)
        };
        let window_start = field("window_start")?.as_u64().ok_or_else(corrupted)?;
        let Value::Array(raw_entries) = field("entries")? else {
            return Err(corrupted());
        };
        let debit_entries = raw_entries
            .iter()
            .map(|entry| {
                let Value::Array(pair) = entry else {
                    return Err(corrupted());
                };
                if pair.len() != 2 {
                    return Err(corrupted());
                }
                Ok((
                    pair[0].as_u64().ok_or_else(corrupted)?,
                    pair[1].as_u64().ok_or_else(corrupted)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let Value::Array(raw_fired) = field("fired")? else {
            return Err(corrupted());
        };
        let fired = raw_fired
            .iter()
            .map(|name| name.as_str().map(str::to_owned).ok_or_else(corrupted))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            window_start,
            entries: debit_entries,
            fired,
        })
    }
}

impl RawValue for ConnectorKeyUsage {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(self.encode()?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(Self::decode(bytes)?)
    }
}

/// Deletes every compiled-cap usage row (charter source tag) for one key.
/// Called by charter approve so a re-stamped charter never inherits
/// positional usage from the previous charter's caps.
pub(super) fn delete_charter_usage_rows_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let doomed = USAGE
        .scan_keys(store, wtxn, id.as_bytes())?
        .into_iter()
        .filter(|(_, row)| {
            EffectorBudgetRowId::from_usage_key(*row)
                .is_some_and(|row| row.source == EffectorBudgetRowSource::Charter)
        })
        .collect::<Vec<_>>();
    for key in &doomed {
        USAGE.delete(store, wtxn, key)?;
    }
    Ok(())
}

// --- Reads and charges --------------------------------------------------------

/// Post-debit read of one budget row (the `self.*` echo shape; GOV-02 wires
/// the meter read around it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectorBudgetRowRead {
    /// The key budget row or compiled-cap row (GOV-10) this read covers.
    pub row: EffectorBudgetRowId,
    pub dimension: EffectorBudgetDimension,
    pub channel_class: Option<String>,
    pub limit: u64,
    pub unit: Option<String>,
    /// Live usage in the current window.
    pub used: u64,
    pub remaining: u64,
    /// `used*100/limit`, capped 100 (`limit == 0` ⇒ 100).
    pub percent_used: u64,
    pub on_exhaust: EffectorBudgetOnExhaust,
    /// Calendar bucket start; 0 for rolling.
    pub window_start: u64,
    /// Thresholds the current window's usage has crossed, ascending — the
    /// TRUE ladder state, computed from live usage rather than parsed from
    /// the stored event-emission memory (which lags when usage advances
    /// without incremental firing: spend settlements, pre-ladder rows).
    pub fired_thresholds: Vec<BudgetThreshold>,
}

/// The `self.*` effector-meter read (ARCHPASS A3): the response-borne budget
/// is an ECHO of this read, never a second delivery lane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectorBudgetRead {
    pub key_ref: EntityId,
    pub connector: String,
    pub status: ConnectorKeyStatus,
    /// Key budget rows and, when a charter is stamped, the compiled-cap rows
    /// (GOV-10) — key rows first, each source ascending.
    pub rows: Vec<EffectorBudgetRowRead>,
    /// A per-grant key's catalog pool (ONE-1794): the catalog key's own read,
    /// under its `key_ref` and with its own row indices, beside this key's.
    /// `None` for any other key, and when this key's charge left the pool to
    /// another key of the same effect. A pool read has no pool of its own.
    pub pool: Option<Box<EffectorBudgetRead>>,
}

/// The budget outcome the gate hands back to dispatch when a governing key's
/// budget stage ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectorBudgetCharge {
    pub key_ref: EntityId,
    /// 1 iff ≥1 Sends-dimension row actually debited this dispatch, else 0
    /// (`NoRows`/`Exhausted` paths return 0).
    pub sends_debit: u64,
    /// Post-debit meter read over EVERY row of the governing key.
    pub read: EffectorBudgetRead,
    /// Rows matched by this dispatch (the binding constraint set for the
    /// receipt `"budget"` field — M4 resolution 2026-07-10).
    pub matched_rows: Vec<EffectorBudgetRowId>,
    /// Threshold events fired by this charge, for the host steering queue
    /// (same contract as `BudgetAdmission.ladder_events`).
    pub ladder_events: Vec<EffectorBudgetLadderEvent>,
    /// The catalog pool's side of a per-grant key's charge (ONE-1794). Its
    /// post-debit read rides `read.pool`. `None` for any other key, and when
    /// the pool was charged through another key of the same effect.
    pub pool: Option<EffectorPoolCharge>,
    /// Every usage entry this charge wrote, the catalog pool's included,
    /// each under its own key: what an outbound send's reservation releases
    /// when the send certainly did not go (FIX 7964). Empty when nothing
    /// debited.
    pub debits: Vec<EffectorBudgetDebit>,
}

impl EffectorBudgetCharge {
    /// The steering messages this charge fired (FIX 3759, FIX 3761): its
    /// key's ladder events, then its catalog pool's, each threshold that
    /// carries one (80% plan, 95% land) once. The reply of the call, or the
    /// wake, that made the charge carries them to the agent.
    #[must_use]
    pub fn steering_messages(&self) -> Vec<String> {
        let pool = self.pool.iter().flat_map(|pool| &pool.ladder_events);
        let mut messages: Vec<String> = Vec::new();
        for event in self.ladder_events.iter().chain(pool) {
            if let Some(signal) = &event.steering
                && !messages.contains(&signal.message)
            {
                messages.push(signal.message.clone());
            }
        }
        messages
    }
}

/// What one charge did to a per-grant key's catalog pool (ONE-1794). It is
/// kept under the catalog key's ref because its rows are the catalog key's
/// own: an `EffectorBudgetLadderEvent` names a row but no key, so the pool's
/// events never join the per-grant key's `ladder_events`. The intent ledger's
/// `BudgetChargeMarker.key_ref` stays the per-grant key; recovery never
/// reads this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectorPoolCharge {
    /// The catalog key whose rows hold the pool.
    pub key_ref: EntityId,
    /// 1 iff ≥1 of the pool's Sends-dimension rows debited, else 0.
    pub sends_debit: u64,
    /// The pool's rows matched by this dispatch.
    pub matched_rows: Vec<EffectorBudgetRowId>,
    /// Threshold events fired on the pool's rows by this charge, for the
    /// same steering queue as the per-grant key's.
    pub ladder_events: Vec<EffectorBudgetLadderEvent>,
}

/// Caller-declared observations that ride along with a dispatch batch.
///
/// Deliberately NON-AUTHORITATIVE: nothing in here selects, rolls, or clears a
/// budget window, stamps a usage entry, or dates a suspension. It is the same
/// split `settle_connector_spend` draws between the declared `cost_occurred_at`
/// and the engine-owned `settled_at` — the caller says when it saw the
/// dispatches; the ledger says when we charged them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConnectorDispatchTelemetry {
    /// When the caller observed the batch. Echoed back in the tally and never
    /// handed to the budget charger.
    pub caller_observed_at: Option<u64>,
}

/// Aggregate result of applying connector-key admission to a sequential batch
/// of send-like dispatches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorKeyDispatchTally {
    pub admitted: u64,
    pub refused: u64,
    /// Dispatches a full count-bound window paced (FIX 8686): uncharged and
    /// not refused, to be admitted again at `paced_until`.
    pub paced: u64,
    /// When the windows that paced the batch all open again, Unix seconds
    /// on the engine's clock; `None` when nothing was paced.
    pub paced_until: Option<u64>,
    pub ladder_events: Vec<EffectorBudgetLadderEvent>,
    /// The catalog key of the pool this batch's per-grant key met (ONE-1794).
    pub pool_key_ref: Option<EntityId>,
    /// Ladder events the batch fired on that pool's rows. Their rows are the
    /// catalog key's own, so they never join `ladder_events`.
    pub pool_ladder_events: Vec<EffectorBudgetLadderEvent>,
    /// The engine-clock sample the batch's first transaction chunk was
    /// accounted against: every window selection, usage entry, suspension
    /// stamp, and op record in a chunk carries that chunk's one sample.
    pub accounted_at: u64,
    /// The sample of the batch's last transaction chunk; equal to
    /// `accounted_at` when the batch fit one chunk (FIX 8683).
    pub last_accounted_at: u64,
    /// Echo of `ConnectorDispatchTelemetry::caller_observed_at`. Telemetry
    /// only — it had no effect on any number above.
    pub caller_observed_at: Option<u64>,
}

impl ConnectorKeyDispatchTally {
    /// Takes one charge's ladder events, the pool's under its catalog key.
    pub(super) fn take_ladder_events(&mut self, charge: EffectorBudgetCharge) {
        self.ladder_events.extend(charge.ladder_events);
        if let Some(pool) = charge.pool {
            self.pool_key_ref = Some(pool.key_ref);
            self.pool_ladder_events.extend(pool.ladder_events);
        }
    }
}

/// Outcome of one budget-stage evaluation over a key's matched rows.
pub(crate) enum EffectorBudgetChargeOutcome {
    /// No budget row matched this effect.
    NoRows(EffectorBudgetCharge),
    /// All matched rows passed; debits applied.
    Charged(EffectorBudgetCharge),
    /// A matched row would exceed (or a spend row is already exhausted);
    /// NO debits were applied. `location` is the first exceeding row in the
    /// meter's row order, under the key that owns it: the catalog key's for
    /// a pool row (FIX 3760).
    Exhausted {
        location: EffectorBudgetLocation,
        on_exhaust: EffectorBudgetOnExhaust,
        charge: EffectorBudgetCharge,
    },
}

fn percent_used(used: u64, limit: u64) -> u64 {
    if limit == 0 {
        return 100;
    }
    let percent = (u128::from(used) * 100) / u128::from(limit);
    u64::try_from(percent.min(100)).unwrap_or(100)
}

fn parse_fired_threshold(name: &str) -> Option<BudgetThreshold> {
    match name {
        "silent50" => Some(BudgetThreshold::Silent50),
        "plan80" => Some(BudgetThreshold::Plan80),
        "land95" => Some(BudgetThreshold::Land95),
        _ => None,
    }
}

/// Thresholds the given usage percentage has crossed, ascending.
fn crossed_thresholds(percent: u64) -> Vec<BudgetThreshold> {
    [
        BudgetThreshold::Silent50,
        BudgetThreshold::Plan80,
        BudgetThreshold::Land95,
    ]
    .into_iter()
    .filter(|threshold| percent >= threshold.percent())
    .collect()
}

pub(super) fn budget_row_read(
    row: EffectorBudgetRowId,
    budget: &EffectorBudget,
    usage: &ConnectorKeyUsage,
) -> EffectorBudgetRowRead {
    let used = usage.used();
    let percent = percent_used(used, budget.limit);
    EffectorBudgetRowRead {
        row,
        dimension: budget.dimension,
        channel_class: budget.channel_class.clone(),
        limit: budget.limit,
        unit: budget.unit.clone(),
        used,
        remaining: budget.limit.saturating_sub(used),
        percent_used: percent,
        on_exhaust: budget.on_exhaust,
        window_start: usage.window_start,
        // The read reports the TRUE ladder state — every threshold the live
        // usage has crossed — not the event-emission memory. Usage can
        // advance without incremental firing (spend settlements never emit
        // per M3b; pre-ladder upgrade rows carry entries with an empty
        // `fired`), and the Exhausted path deliberately emits nothing (M5b
        // carry-read-only), so a denial's history must be computed from the
        // usage itself or a jump-to-exhausted row would read as
        // signal-silent. Post-touch, the stored `fired` (the single-fire
        // memory) is always a subset of this per the M5a re-arm rule, so for
        // incrementally-fired rows the two coincide exactly.
        fired_thresholds: crossed_thresholds(percent),
    }
}

fn budget_debit_amount(dimension: EffectorBudgetDimension, send_like: bool) -> u64 {
    match dimension {
        // Sends count gate-admitted sends; lifecycle intents (send_ref None)
        // never eat a sends budget.
        EffectorBudgetDimension::Sends => u64::from(send_like),
        // Rate is a verb-agnostic limiter on effector calls.
        EffectorBudgetDimension::Rate => 1,
        // Spend debits 0 at admission; actual costs settle post-hoc.
        EffectorBudgetDimension::Spend => 0,
    }
}

/// Every budget row of a record in the meter's row order: key rows, then
/// (when a charter is stamped — GOV-10) compiled-cap rows, each ascending.
/// One row-set union so evaluate-all-then-apply-all atomicity spans key AND
/// compiled rows. Every row is kept, however many the record holds.
fn record_budget_rows(record: &ConnectorKeyRecord) -> Vec<(EffectorBudgetRowId, &EffectorBudget)> {
    let key_rows = record
        .budgets
        .iter()
        .enumerate()
        .map(|(offset, budget)| (EffectorBudgetRowId::key(row_ordinal(offset)), budget));
    let charter_rows = record
        .charter
        .iter()
        .flat_map(|charter| charter.compiled.channel_caps.iter().enumerate())
        .map(|(offset, budget)| (EffectorBudgetRowId::charter(row_ordinal(offset)), budget));
    key_rows.chain(charter_rows).collect()
}

pub(super) struct BudgetRowState<'a> {
    row: EffectorBudgetRowId,
    budget: &'a EffectorBudget,
    usage: ConnectorKeyUsage,
    amount: u64,
    matched: bool,
}

pub(super) fn load_budget_row_states<'a>(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key_id: &EntityId,
    record: &'a ConnectorKeyRecord,
    effect_channel: Option<&str>,
    send_like: bool,
    now: u64,
) -> Result<Vec<BudgetRowState<'a>>> {
    let mut states = Vec::new();
    for (row, budget) in record_budget_rows(record) {
        let mut usage = USAGE
            .get(store, txn, &(*key_id, row.usage_key()))?
            .unwrap_or_default();
        usage.touch(&budget.window, budget.limit, now);
        let matched = effect_channel.is_some_and(|channel| {
            budget
                .channel_class
                .as_deref()
                .is_none_or(|channel_class| channel_class == channel)
        });
        let amount = if matched {
            budget_debit_amount(budget.dimension, send_like)
        } else {
            0
        };
        states.push(BudgetRowState {
            row,
            budget,
            usage,
            amount,
            matched,
        });
    }
    Ok(states)
}

pub(super) fn budget_read_from_states(
    key_id: &EntityId,
    record: &ConnectorKeyRecord,
    states: &[BudgetRowState<'_>],
) -> EffectorBudgetRead {
    EffectorBudgetRead {
        key_ref: *key_id,
        connector: record.connector.clone(),
        status: record.status,
        rows: states
            .iter()
            .map(|state| budget_row_read(state.row, state.budget, &state.usage))
            .collect(),
        pool: None,
    }
}

/// The read of a per-grant key's catalog pool at `now` (ONE-1794): the
/// catalog key's own rows, no debit. `None` for any other key.
pub(super) fn budget_pool_read_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &ConnectorKeyRecord,
    now: u64,
) -> Result<Option<Box<EffectorBudgetRead>>> {
    let Some((catalog_id, catalog, _)) = catalog_budget_pool_in_txn(store, txn, key)? else {
        return Ok(None);
    };
    let states = load_budget_row_states(store, txn, &catalog_id, &catalog, None, false, now)?;
    Ok(Some(Box::new(budget_read_from_states(
        &catalog_id,
        &catalog,
        &states,
    ))))
}

/// The shared pool a per-grant key's charges also meet: its catalog
/// connector's own budget rows and compiled caps, matched on the ordinary
/// `mcp:{server}` channel and kept under the catalog key's id. One cap on a
/// catalog then holds across every grant derived from it, instead of
/// multiplying with each new grant (ONE-1794). `None` for any other key.
fn catalog_budget_pool_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &ConnectorKeyRecord,
) -> Result<Option<(EntityId, ConnectorKeyRecord, String)>> {
    derived_key_catalog_in_txn(store, txn, key)
}
