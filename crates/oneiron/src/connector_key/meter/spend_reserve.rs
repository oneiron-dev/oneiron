//! Spend reserved before a call (FIX 8689). A Spend row whose owner selected
//! `preauthorize_estimate_then_settle` takes the verb's declared price as a
//! usage entry at admission, beside the call's other debits, so the send's
//! reservation (FIX 7964) carries it: a delivered send keeps it as its
//! charge, and one that certainly never went gives it back. A price that
//! does not fit a row's remaining limit denies the call as an exhausted Spend
//! row does, since the owner chose to authorize money before it goes. A verb
//! with no declared price in a row's unit is unpriced there: measured, never
//! refused. A `settle_only` row is untouched.

use super::*;
use crate::connector_key::record::{
    ConnectorSpendBasis, ConnectorSpendEstimate, EffectorBudgetReservePolicy,
};

/// What the preauthorizing Spend rows a call meets say of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SpendReserve {
    /// No matched row preauthorizes: the call settles its cost after, as
    /// before.
    SettleOnly,
    /// Every preauthorizing row had room. `debits` are the entries this
    /// reserve wrote (none when it only evaluated, or nothing was priced).
    Reserved {
        debits: Vec<EffectorBudgetDebit>,
        basis: ConnectorSpendBasis,
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
    let mut preauthorized = false;
    let mut priced = false;
    for (owner, record, states) in &sets {
        for state in states
            .iter()
            .filter(|state| state.matched && preauthorizes(state.budget))
        {
            preauthorized = true;
            let Some(price) = row_price(state.budget, price) else {
                continue;
            };
            priced = true;
            if state.usage.used().saturating_add(price.minor_units) > state.budget.limit {
                let location = EffectorBudgetLocation {
                    key_ref: *owner,
                    row: state.row,
                };
                let on_exhaust = state.budget.on_exhaust;
                if on_exhaust == EffectorBudgetOnExhaust::Suspend
                    && record.status == ConnectorKeyStatus::Active
                {
                    suspend_connector_key_in_txn(
                        store,
                        wtxn,
                        owner,
                        record,
                        budget_exhausted_reason(&location),
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
    if !preauthorized {
        return Ok(SpendReserve::SettleOnly);
    }
    let basis = match price.filter(|_| priced) {
        Some(price) => ConnectorSpendBasis::Estimated(price.clone()),
        None => ConnectorSpendBasis::Unpriced,
    };
    let mut debits = Vec::new();
    if apply {
        for (owner, _, states) in &mut sets {
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
                state.usage.entries.push((now, price.minor_units));
                USAGE.put(store, wtxn, &(*owner, state.row.usage_key()), &state.usage)?;
                debits.push(EffectorBudgetDebit {
                    key_ref: *owner,
                    row: state.row,
                    amount: price.minor_units,
                    at: now,
                });
            }
        }
    }
    Ok(SpendReserve::Reserved { debits, basis })
}

/// `price` where it is in `budget`'s own unit; no unit is converted.
fn row_price<'a>(
    budget: &EffectorBudget,
    price: Option<&'a ConnectorSpendEstimate>,
) -> Option<&'a ConnectorSpendEstimate> {
    price.filter(|price| budget.unit.as_deref() == Some(price.unit.as_str()))
}
