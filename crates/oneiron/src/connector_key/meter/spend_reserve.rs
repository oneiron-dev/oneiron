//! Spend reserved before a call (FIX 8689). A Spend row whose owner selected
//! `preauthorize_estimate_then_settle` takes the verb's declared price as a
//! usage entry at admission, beside the call's other debits, so the send's
//! reservation (FIX 7964) carries it: a delivered send keeps it as its
//! charge, and one that certainly never went gives it back. A price that
//! does not fit a row's remaining limit denies the call as an exhausted Spend
//! row does, since the owner chose to authorize money before it goes. A verb
//! with no declared price in a row's unit is unpriced there: measured, never
//! refused. A `settle_only` row is untouched. Once a delivered send's
//! provider reports its actual cost (FIX 11662), the estimate comes out of
//! those rows and the actual goes in.

use super::*;
use crate::connector_key::record::{
    ConnectorSpendBasis, ConnectorSpendEstimate, EffectorBudgetReservePolicy,
};
use crate::connector_key::txn::read_connector_key_in_txn;

/// What the preauthorizing Spend rows a call meets say of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SpendReserve {
    /// No matched row preauthorizes: the call settles its cost after, as
    /// before.
    SettleOnly,
    /// Every preauthorizing row had room. `debits` are the entries this
    /// reserve wrote (none when it only evaluated, or nothing was priced);
    /// `rows` every preauthorizing row the call met, priced or not, which a
    /// reported actual cost is reconciled on.
    Reserved {
        debits: Vec<EffectorBudgetDebit>,
        basis: ConnectorSpendBasis,
        rows: Vec<EffectorSpendReservationRow>,
    },
    /// A preauthorizing row has no room for the price: the call is denied,
    /// and a row the owner set to suspend suspended its key. Nothing debits.
    Exhausted {
        location: EffectorBudgetLocation,
        on_exhaust: EffectorBudgetOnExhaust,
    },
}

fn preauthorizes(budget: &EffectorBudget) -> bool {
    budget.dimension == EffectorBudgetDimension::Spend
        && budget.reserve_policy
            == Some(EffectorBudgetReservePolicy::PreauthorizeEstimateThenSettle)
}

/// Reads, and when `apply` reserves, `price` on every matched preauthorizing
/// Spend row of `key_id` and, when `pool`, of its catalog's shared pool, at
/// the engine instant `now`: every row is evaluated before any debits. An
/// exhausted row the owner set to suspend suspends its key here, as the
/// meter's own exhaustion does.
///
/// # Errors
/// Storage and row-codec faults.
#[expect(clippy::too_many_arguments)]
pub(crate) fn reserve_connector_spend_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    key_id: &EntityId,
    key: &ConnectorKeyRecord,
    effect_channel: &str,
    price: Option<&ConnectorSpendEstimate>,
    now: u64,
    pool: bool,
    apply: bool,
) -> Result<SpendReserve> {
    let catalog = if pool {
        catalog_budget_pool_in_txn(store, wtxn, key)?
    } else {
        None
    };
    let mut sets = vec![(
        *key_id,
        key,
        load_budget_row_states(store, wtxn, key_id, key, Some(effect_channel), false, now)?,
    )];
    if let Some((catalog_id, catalog, channel)) = catalog.as_ref() {
        sets.push((
            *catalog_id,
            catalog,
            load_budget_row_states(
                store,
                wtxn,
                catalog_id,
                catalog,
                Some(channel.as_str()),
                false,
                now,
            )?,
        ));
    }
    let mut rows = Vec::new();
    let mut priced = false;
    for (owner, record, states) in &sets {
        for state in states
            .iter()
            .filter(|state| state.matched && preauthorizes(state.budget))
        {
            rows.push(EffectorSpendReservationRow {
                key_ref: *owner,
                row: state.row,
                approval: EffectorBudgetApproval::capture(record, state.row)?,
            });
            let Some(price) = row_price(state.budget, price) else {
                continue;
            };
            priced = true;
            if overruns(state, price) {
                let location = EffectorBudgetLocation {
                    key_ref: *owner,
                    row: state.row,
                };
                let on_exhaust = state.budget.on_exhaust;
                if on_exhaust == EffectorBudgetOnExhaust::Suspend {
                    suspend_connector_key_in_txn(
                        store,
                        wtxn,
                        owner,
                        record,
                        SuspendCause::BudgetExhausted(&location),
                        now,
                    )?;
                }
                return Ok(SpendReserve::Exhausted {
                    location,
                    on_exhaust,
                });
            }
        }
    }
    if rows.is_empty() {
        return Ok(SpendReserve::SettleOnly);
    }
    let basis = match price.filter(|_| priced) {
        Some(price) => ConnectorSpendBasis::Estimated(price.clone()),
        None => ConnectorSpendBasis::Unpriced,
    };
    let mut debits = Vec::new();
    if apply {
        for (owner, record, states) in &mut sets {
            for state in states
                .iter_mut()
                .filter(|state| state.matched && preauthorizes(state.budget))
            {
                let Some(price) = row_price(state.budget, price) else {
                    continue;
                };
                if price.minor_units == 0 {
                    continue;
                }
                let entry = UsageEntry::settled(store, wtxn, now, price.minor_units)?;
                state.usage.entries.push(entry);
                USAGE.put(store, wtxn, &(*owner, state.row.usage_key()), &state.usage)?;
                debits.push(EffectorBudgetDebit {
                    entry_id: entry.id,
                    key_ref: *owner,
                    row: state.row,
                    approval: EffectorBudgetApproval::capture(record, state.row)?,
                    amount: price.minor_units,
                    at: now,
                });
            }
        }
    }
    Ok(SpendReserve::Reserved {
        debits,
        basis,
        rows,
    })
}

/// What reconciling one delivered send's preauthorized spend to its
/// provider's reported cost wrote (FIX 11662).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SpendReconciliation {
    /// The estimate entries taken back out of their rows.
    pub(crate) released: Vec<EffectorBudgetDebit>,
    /// The actual entries written in their place.
    pub(crate) written: Vec<EffectorBudgetDebit>,
}

/// Reconciles a delivered send's preauthorized spend to `actual`, the cost
/// its provider reported, on each of `rows` that is still a preauthorizing
/// Spend row in `actual`'s unit: that row's entry among `estimates` comes
/// out when its window still holds it, and the actual goes in at the engine
/// instant `now`, when the ledger learned it. An actual past the row's limit
/// is written as it is, since the effect already occurred: a row the owner
/// set to suspend that it fills suspends its key, as a settlement does, and
/// the next call meets the full row. A row no longer there, or in another
/// unit, is left as it stands; no unit is converted.
///
/// # Errors
/// Storage and row-codec faults.
pub(crate) fn reconcile_connector_spend_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    rows: &[EffectorSpendReservationRow],
    estimates: &[EffectorBudgetDebit],
    actual: &ConnectorSpendEstimate,
    now: u64,
) -> Result<SpendReconciliation> {
    let mut reconciliation = SpendReconciliation::default();
    for reserved in rows {
        let location = EffectorBudgetLocation {
            key_ref: reserved.key_ref,
            row: reserved.row,
        };
        let Some(record) = read_connector_key_in_txn(store, wtxn, &location.key_ref)? else {
            continue;
        };
        if !reserved.approval.matches(&record, location.row) {
            continue;
        }
        let Some(budget) = budget_at(&record, location.row) else {
            continue;
        };
        if !preauthorizes(budget) || budget.unit.as_deref() != Some(actual.unit.as_str()) {
            continue;
        }
        let usage_key = (location.key_ref, location.row.usage_key());
        let mut usage = USAGE.get(store, wtxn, &usage_key)?.unwrap_or_default();
        if let Some(estimate) = estimates.iter().find(|debit| {
            debit.key_ref == location.key_ref
                && debit.row == location.row
                && debit.approval == reserved.approval
        }) && let Some(position) = usage
            .entries
            .iter()
            .position(|entry| entry.id == estimate.entry_id)
        {
            usage.entries.remove(position);
            reconciliation.released.push(*estimate);
        }
        usage.touch(&budget.window, budget.limit, now);
        if actual.minor_units > 0 {
            let entry = UsageEntry::settled(store, wtxn, now, actual.minor_units)?;
            usage.entries.push(entry);
            reconciliation.written.push(EffectorBudgetDebit {
                entry_id: entry.id,
                key_ref: location.key_ref,
                row: location.row,
                approval: reserved.approval,
                amount: actual.minor_units,
                at: now,
            });
        }
        USAGE.put(store, wtxn, &usage_key, &usage)?;
        if usage.used() >= budget.limit && budget.on_exhaust == EffectorBudgetOnExhaust::Suspend {
            suspend_connector_key_in_txn(
                store,
                wtxn,
                &location.key_ref,
                &record,
                SuspendCause::BudgetExhausted(&location),
                now,
            )?;
        }
    }
    Ok(reconciliation)
}

/// The budget row `row` names on `record`: a key row or a compiled cap.
fn budget_at(record: &ConnectorKeyRecord, row: EffectorBudgetRowId) -> Option<&EffectorBudget> {
    let offset = usize::try_from(row.index).ok()?;
    match row.source {
        EffectorBudgetRowSource::Key => record.budgets.get(offset),
        EffectorBudgetRowSource::Charter => record
            .charter
            .as_ref()
            .and_then(|charter| charter.compiled.channel_caps.get(offset)),
    }
}

/// `price` where it is in `budget`'s own unit; no unit is converted.
/// The price `tool` declares on `key`'s governing slate, the one a
/// reservation takes (FIX 8689); `None` for a tool that declares none.
///
/// # Errors
/// Storage and slate-codec faults.
pub(crate) fn tool_spend_price_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &ConnectorKeyRecord,
    tool: &str,
) -> Result<Option<ConnectorSpendEstimate>> {
    Ok(
        crate::connector_key::governing_slate_in_txn(store, txn, key)?
            .and_then(|(_, slate)| slate.tool(tool).and_then(|row| row.price.clone())),
    )
}

/// Whether `price` overruns `state`'s remaining limit: the one rule a
/// reservation denies on.
fn overruns(state: &BudgetRowState<'_>, price: &ConnectorSpendEstimate) -> bool {
    state.usage.used().saturating_add(price.minor_units) > state.budget.limit
}

/// The first matched preauthorizing Spend row of `key_id`, and when `pool`
/// of its catalog's shared pool, that `price` overruns at `now`, in the order
/// [`reserve_connector_spend_in_txn`] meets them, read on `txn`: the row that
/// reservation denies on, found without suspending or debiting anything
/// (FIX 22102). `None` when every row has room or none is priced.
///
/// # Errors
/// Storage and row-codec faults.
#[expect(clippy::too_many_arguments)]
pub(crate) fn spend_overrun_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key_id: &EntityId,
    key: &ConnectorKeyRecord,
    effect_channel: &str,
    price: Option<&ConnectorSpendEstimate>,
    now: u64,
    pool: bool,
) -> Result<Option<(EffectorBudgetLocation, EffectorBudgetOnExhaust)>> {
    let catalog = if pool {
        catalog_budget_pool_in_txn(store, txn, key)?
    } else {
        None
    };
    let mut sets = vec![(
        *key_id,
        load_budget_row_states(store, txn, key_id, key, Some(effect_channel), false, now)?,
    )];
    if let Some((catalog_id, catalog, channel)) = catalog.as_ref() {
        sets.push((
            *catalog_id,
            load_budget_row_states(
                store,
                txn,
                catalog_id,
                catalog,
                Some(channel.as_str()),
                false,
                now,
            )?,
        ));
    }
    for (owner, states) in &sets {
        for state in states
            .iter()
            .filter(|state| state.matched && preauthorizes(state.budget))
        {
            if let Some(price) = row_price(state.budget, price)
                && overruns(state, price)
            {
                return Ok(Some((
                    EffectorBudgetLocation {
                        key_ref: *owner,
                        row: state.row,
                    },
                    state.budget.on_exhaust,
                )));
            }
        }
    }
    Ok(None)
}

fn row_price<'a>(
    budget: &EffectorBudget,
    price: Option<&'a ConnectorSpendEstimate>,
) -> Option<&'a ConnectorSpendEstimate> {
    price.filter(|price| budget.unit.as_deref() == Some(price.unit.as_str()))
}
