//! Effector budget preflight and charge: the pooled and per-key passes over
//! the budget rows a dispatch spends.
//! Entry: `charge_effector_budgets`. Defines its own items; windows, usage and reads stay in `meter`.

use super::*;

impl EffectorBudgetCharge {
    /// Folds the catalog pool's own charge into this per-grant key's: the
    /// pool's read rides `read.pool`, the rest `pool`.
    fn meet_pool(&mut self, mut pool: Self) {
        self.read.pool = Some(Box::new(pool.read));
        self.debits.append(&mut pool.debits);
        self.pool = Some(EffectorPoolCharge {
            key_ref: pool.key_ref,
            sends_debit: pool.sends_debit,
            matched_rows: pool.matched_rows,
            ladder_events: pool.ladder_events,
        });
    }
}

impl EffectorBudgetChargeOutcome {
    fn charge_mut(&mut self) -> &mut EffectorBudgetCharge {
        match self {
            Self::NoRows(charge) | Self::Charged(charge) | Self::Exhausted { charge, .. } => charge,
        }
    }
}

/// One key's charge as evaluated and never applied: its read and matched
/// rows, no debit and no ladder events (M5b carry-read-only).
fn evaluated_charge(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key_id: &EntityId,
    record: &ConnectorKeyRecord,
    effect_channel: &str,
    send_like: bool,
    now: u64,
) -> Result<EffectorBudgetCharge> {
    let states = load_budget_row_states(
        store,
        txn,
        key_id,
        record,
        Some(effect_channel),
        send_like,
        now,
    )?;
    Ok(EffectorBudgetCharge {
        key_ref: *key_id,
        sends_debit: 0,
        read: budget_read_from_states(key_id, record, &states),
        matched_rows: states
            .iter()
            .filter(|state| state.matched)
            .map(|state| state.row_index)
            .collect(),
        ladder_events: Vec::new(),
        pool: None,
        debits: Vec::new(),
    })
}

/// Two distinct per-grant keys of one catalog share its pool. One effect
/// charged to both debits the pool through the first only; the second
/// meets its own rows (`pool: false` below).
pub(crate) fn shares_budget_pool(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    first: &ConnectorKeyRecord,
    second: &ConnectorKeyRecord,
) -> Result<bool> {
    let Some((pool, ..)) = catalog_budget_pool_in_txn(store, txn, first)? else {
        return Ok(false);
    };
    Ok(catalog_budget_pool_in_txn(store, txn, second)?.is_some_and(|(other, ..)| other == pool))
}

/// [`preflight_effector_budgets`], or the key's own rows alone when `pool`
/// is false.
#[expect(clippy::too_many_arguments)]
pub(crate) fn preflight_effector_budgets_pooled(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key_id: &EntityId,
    record: &ConnectorKeyRecord,
    effect_channel: &str,
    send_like: bool,
    now: u64,
    pool: bool,
) -> Result<Option<(u16, EffectorBudgetOnExhaust)>> {
    if pool {
        preflight_effector_budgets(store, txn, key_id, record, effect_channel, send_like, now)
    } else {
        preflight_key_budgets(store, txn, key_id, record, effect_channel, send_like, now)
    }
}

/// [`charge_effector_budgets`], or the key's own rows alone when `pool` is
/// false.
#[expect(clippy::too_many_arguments)]
pub(crate) fn charge_effector_budgets_pooled(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    key_id: &EntityId,
    key: &mut ConnectorKeyRecord,
    effect_channel: &str,
    send_like: bool,
    now: u64,
    pool: bool,
) -> Result<EffectorBudgetChargeOutcome> {
    if pool {
        charge_effector_budgets(store, wtxn, key_id, key, effect_channel, send_like, now)
    } else {
        charge_key_budgets(store, wtxn, key_id, key, effect_channel, send_like, now)
    }
}

/// Read-only preflight for a set of connector keys charged in ONE Gate
/// transaction. Callers preflight every distinct key before writing usage to
/// any of them, so a later exhausted key cannot partially debit an earlier.
/// A per-grant key's preflight also reads its catalog's shared pool.
pub(crate) fn preflight_effector_budgets(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key_id: &EntityId,
    record: &ConnectorKeyRecord,
    effect_channel: &str,
    send_like: bool,
    now: u64,
) -> Result<Option<(u16, EffectorBudgetOnExhaust)>> {
    if let Some(exhausted) =
        preflight_key_budgets(store, txn, key_id, record, effect_channel, send_like, now)?
    {
        return Ok(Some(exhausted));
    }
    let Some((catalog_id, catalog, channel)) = catalog_budget_pool_in_txn(store, txn, record)?
    else {
        return Ok(None);
    };
    preflight_key_budgets(store, txn, &catalog_id, &catalog, &channel, send_like, now)
}

fn preflight_key_budgets(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key_id: &EntityId,
    record: &ConnectorKeyRecord,
    effect_channel: &str,
    send_like: bool,
    now: u64,
) -> Result<Option<(u16, EffectorBudgetOnExhaust)>> {
    let states = load_budget_row_states(
        store,
        txn,
        key_id,
        record,
        Some(effect_channel),
        send_like,
        now,
    )?;
    Ok(states
        .iter()
        .find(|state| {
            if !state.matched {
                return false;
            }
            let used = state.usage.used();
            match state.budget.dimension {
                EffectorBudgetDimension::Spend => used >= state.budget.limit,
                _ => used.saturating_add(state.amount) > state.budget.limit,
            }
        })
        .map(|state| (state.row_index, state.budget.on_exhaust)))
}

/// Charges one admitted external effect to a key's budget rows and, for a
/// per-grant key, to its catalog's shared pool: both are evaluated before
/// either debits. The charge and its read stay the key's own; the pool's
/// side rides `charge.pool` and `charge.read.pool` under the catalog key's
/// ref (ONE-1794).
///
/// An exhausted catalog pool comes back as `Exhausted` with `Refuse`, after
/// the catalog row's own on-exhaust has run: a `Suspend` row suspends the
/// catalog key, which holds this key with it. The caller then must not
/// suspend this key in its own name, or the catalog's resume would not
/// lift it.
pub(crate) fn charge_effector_budgets(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    key_id: &EntityId,
    key: &mut ConnectorKeyRecord,
    effect_channel: &str,
    send_like: bool,
    now: u64,
) -> Result<EffectorBudgetChargeOutcome> {
    let Some((catalog_id, mut catalog, channel)) = catalog_budget_pool_in_txn(store, wtxn, key)?
    else {
        return charge_key_budgets(store, wtxn, key_id, key, effect_channel, send_like, now);
    };
    if preflight_key_budgets(store, wtxn, key_id, key, effect_channel, send_like, now)?.is_none()
        && let Some((row_index, on_exhaust)) =
            preflight_key_budgets(store, wtxn, &catalog_id, &catalog, &channel, send_like, now)?
    {
        let held = on_exhaust == EffectorBudgetOnExhaust::Suspend
            && catalog.status == ConnectorKeyStatus::Active;
        if held {
            catalog = suspend_connector_key_in_txn(
                store,
                wtxn,
                &catalog_id,
                &catalog,
                budget_exhausted_reason(row_index),
                now,
            )?;
        }
        let mut charge =
            evaluated_charge(store, wtxn, key_id, key, effect_channel, send_like, now)?;
        if held {
            charge.read.status = ConnectorKeyStatus::Suspended;
        }
        charge.meet_pool(evaluated_charge(
            store,
            wtxn,
            &catalog_id,
            &catalog,
            &channel,
            send_like,
            now,
        )?);
        return Ok(EffectorBudgetChargeOutcome::Exhausted {
            row_index,
            on_exhaust: EffectorBudgetOnExhaust::Refuse,
            charge,
        });
    }
    let mut outcome = charge_key_budgets(store, wtxn, key_id, key, effect_channel, send_like, now)?;
    let pool = if matches!(outcome, EffectorBudgetChargeOutcome::Exhausted { .. }) {
        // The key's own row refused first, so nothing debits, the pool
        // included: echo the pool as evaluated.
        evaluated_charge(store, wtxn, &catalog_id, &catalog, &channel, send_like, now)?
    } else {
        match charge_key_budgets(
            store,
            wtxn,
            &catalog_id,
            &mut catalog,
            &channel,
            send_like,
            now,
        )? {
            EffectorBudgetChargeOutcome::NoRows(pool)
            | EffectorBudgetChargeOutcome::Charged(pool) => pool,
            // Preflighted above under this writer: fail the transaction
            // rather than persist the key's debit alone.
            EffectorBudgetChargeOutcome::Exhausted { .. } => {
                return Err(Error::InvariantViolation(
                    "catalog budget changed inside the charge",
                ));
            }
        }
    };
    outcome.charge_mut().meet_pool(pool);
    Ok(outcome)
}

/// Evaluates and (only when every matched row passes) debits a key's budget
/// rows for one admitted external effect. Evaluate-all-then-apply-all across
/// the key/compiled union: an exhausted outcome applies NO debits. The charge
/// carries the full post-debit meter read, the matched row indices, and the
/// ladder events fired by this charge (GOV-02, ONE-1418).
fn charge_key_budgets(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    key_id: &EntityId,
    key: &mut ConnectorKeyRecord,
    effect_channel: &str,
    send_like: bool,
    now: u64,
) -> Result<EffectorBudgetChargeOutcome> {
    let mut states = load_budget_row_states(
        store,
        wtxn,
        key_id,
        key,
        Some(effect_channel),
        send_like,
        now,
    )?;
    let matched_rows: Vec<u16> = states
        .iter()
        .filter(|state| state.matched)
        .map(|state| state.row_index)
        .collect();

    if matched_rows.is_empty() {
        let read = budget_read_from_states(key_id, key, &states);
        return Ok(EffectorBudgetChargeOutcome::NoRows(EffectorBudgetCharge {
            key_ref: *key_id,
            sends_debit: 0,
            read,
            matched_rows,
            ladder_events: Vec::new(),
            pool: None,
            debits: Vec::new(),
        }));
    }

    // Evaluate ALL matched rows before applying ANY debit; report the first
    // exceeding row in ascending row-index order (key rows before compiled).
    let exhausted = states.iter().find(|state| {
        if !state.matched {
            return false;
        }
        let used = state.usage.used();
        match state.budget.dimension {
            // Spend debits 0 at admission and refuses when already exhausted.
            EffectorBudgetDimension::Spend => used >= state.budget.limit,
            _ => used.saturating_add(state.amount) > state.budget.limit,
        }
    });
    if let Some(state) = exhausted {
        let row_index = state.row_index;
        let on_exhaust = state.budget.on_exhaust;
        // Carry-read-only (M5b resolution 2026-07-10): the exhaustion path
        // fires NO new ladder events and persists nothing — the signal
        // history rides the read's `fired_thresholds`.
        let read = budget_read_from_states(key_id, key, &states);
        return Ok(EffectorBudgetChargeOutcome::Exhausted {
            row_index,
            on_exhaust,
            charge: EffectorBudgetCharge {
                key_ref: *key_id,
                sends_debit: 0,
                read,
                matched_rows,
                ladder_events: Vec::new(),
                pool: None,
                debits: Vec::new(),
            },
        });
    }

    let mut sends_debit = 0;
    let mut ladder_events = Vec::new();
    let mut debits = Vec::new();
    for state in states.iter_mut().filter(|state| state.matched) {
        if state.amount > 0 {
            state.usage.entries.push((now, state.amount));
            debits.push(EffectorBudgetDebit {
                key_ref: *key_id,
                row_index: state.row_index,
                amount: state.amount,
                at: now,
            });
            if state.budget.dimension == EffectorBudgetDimension::Sends {
                sends_debit = 1;
            }
        }
        // Fire ladder thresholds crossed by the post-debit usage, once per
        // window per row (persisted in `fired`). Spend rows advance only via
        // settlement — spend-ladder signals are an explicit v1 non-goal (M3b).
        if state.budget.dimension != EffectorBudgetDimension::Spend {
            let percent = percent_used(state.usage.used(), state.budget.limit);
            for threshold in [
                BudgetThreshold::Silent50,
                BudgetThreshold::Plan80,
                BudgetThreshold::Land95,
            ] {
                let name = budget_threshold_fired_name(threshold);
                if percent >= threshold.percent()
                    && !state.usage.fired.iter().any(|fired| fired == name)
                {
                    state.usage.fired.push(name.to_owned());
                    // Each event carries the row that fired it: a dispatch
                    // matching several rows can cross the same threshold on
                    // more than one, and the consumer must be able to tell
                    // "sends at 80%" from "rate at 80%".
                    ladder_events.push(BudgetLadderEvent {
                        threshold,
                        steering: effector_steering_signal(threshold),
                        row_index: Some(state.row_index),
                    });
                }
            }
        }
        USAGE.put(
            store,
            wtxn,
            &(*key_id, state.row_index.to_be_bytes()),
            &state.usage,
        )?;
    }

    let read = budget_read_from_states(key_id, key, &states);
    Ok(EffectorBudgetChargeOutcome::Charged(EffectorBudgetCharge {
        key_ref: *key_id,
        sends_debit,
        read,
        matched_rows,
        ladder_events,
        pool: None,
        debits,
    }))
}
