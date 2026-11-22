//! How the owner's answer about a held run applies, in the answer's own
//! write: an approved overdraft, added dollars, or the free local route. Each
//! resumes the run as the owner.

use super::*;

/// The owner `by`'s approved overdraft of `cap_units` for the held run
/// rooted at `root`, in the answer's write: the run's overdraft row, its open
/// root spend scope raised by the cap, and the run resumed as `by`. `false`
/// when the run is no longer held, or the owner may not overdraft it.
pub(super) fn approve_overdraft_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    root: AttemptId,
    by: EntityId,
    seq: u64,
    cap_units: u64,
    now: u64,
) -> Result<bool> {
    if cap_units == 0 {
        return Err(invalid("an overdraft names a cap above zero"));
    }
    let dispatcher = AgentDispatcher::new(vault);
    if !dispatcher.budget_held_in_txn(wtxn, root)?
        || !overdraft_open_to_in_txn(vault, wtxn, root, by)?
    {
        return Ok(false);
    }
    OVERDRAFT.put(
        &vault.store,
        wtxn,
        &root,
        &RunOverdraft {
            cap_units,
            ask: seq,
            approved_at: now,
        },
    )?;
    raise_root_scope_in_txn(vault, wtxn, root, by, cap_units, now, "run overdraft")?;
    dispatcher.resume_budget_hold_in_txn(wtxn, root, &by.to_hex(), now)?;
    Ok(true)
}

/// Raises the open root scope ([`run_root_scope_in_txn`]) of the run rooted
/// at `root` by `units`, as the owner `by`'s grant, and wakes every budget
/// trap the new room covers. A run with no root scope raises nothing.
fn raise_root_scope_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    root: AttemptId,
    by: EntityId,
    units: u64,
    now: u64,
    what: &'static str,
) -> Result<()> {
    if let Some(mut scope) = run_root_scope_in_txn(vault, wtxn, root)? {
        let scope_id = scope.scope.clone();
        scope.cap_units = scope
            .cap_units
            .checked_add(units)
            .ok_or(crate::Error::ArithmeticOverflow(what))?;
        let now_ms = now.saturating_mul(1000);
        if let Some(payer) = &mut scope.payer {
            payer.granted_by = Some(by);
            payer.at_ms = now_ms;
        }
        SCOPE.put(&vault.store, wtxn, &scope_id.0, &scope)?;
        crate::llm::wake_budget_traps_in_txn(vault, wtxn, &scope_id, now_ms)?;
    }
    Ok(())
}

/// The owner `by`'s `add_funds` answer to ask `seq`, naming
/// `amount_usd_micros`, for the held run rooted at `root`, in the answer's
/// write: the whole units the amount buys at the vault's USD quote raise the
/// run's open root scope for good, the amount is recorded, each of the run's
/// meters takes the units once (the run's grant row, as an overdraft's), and
/// the run resumes as `by`. `false` when the run is no longer held, or the
/// owner may not raise its scope.
///
/// # Errors
///
/// A zero amount, an amount that buys no whole unit, no USD price for the
/// scope's unit; storage errors.
pub(super) fn add_funds_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    root: AttemptId,
    by: EntityId,
    seq: u64,
    amount_usd_micros: u64,
    now: u64,
) -> Result<bool> {
    let dispatcher = AgentDispatcher::new(vault);
    if !dispatcher.budget_held_in_txn(wtxn, root)?
        || !overdraft_open_to_in_txn(vault, wtxn, root, by)?
    {
        return Ok(false);
    }
    let price = run_funds_price_in_txn(vault, wtxn, root)?
        .ok_or_else(|| invalid("the run's budget unit has no USD price, or no open root scope"))?;
    let units = funds_units(&price, amount_usd_micros)?;
    raise_root_scope_in_txn(vault, wtxn, root, by, units, now, "run add_funds")?;
    // The raise alone leaves a step whose own line is spent held again at
    // its next call: its meter takes the bought units once, as it takes an
    // overdraft's cap (Engine ruling RUNBUDGET-ADDFUNDS-METER = A). The next
    // hold deletes the grant; the raise stays.
    OVERDRAFT.put(
        &vault.store,
        wtxn,
        &root,
        &RunOverdraft {
            cap_units: units,
            ask: seq,
            approved_at: now,
        },
    )?;
    record_funds_in_txn(
        vault,
        wtxn,
        root,
        RunFundsEntry {
            usd_micros: amount_usd_micros,
            units,
            price,
            ask: seq,
            added_at: now,
        },
    )?;
    dispatcher.resume_budget_hold_in_txn(wtxn, root, &by.to_hex(), now)?;
    Ok(true)
}

/// The owner `by`'s choice, answering ask `seq`, to continue the held run
/// rooted at `root` on the free local chat model its hold offered, in the
/// answer's write: the local route chosen and the run resumed as `by`. `false`
/// when the run is no longer held, no local model was offered, or the run is
/// not the owner's.
pub(super) fn continue_on_local_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    root: AttemptId,
    by: EntityId,
    seq: u64,
    now: u64,
) -> Result<bool> {
    let dispatcher = AgentDispatcher::new(vault);
    if !dispatcher.budget_held_in_txn(wtxn, root)?
        || !overdraft_open_to_in_txn(vault, wtxn, root, by)?
    {
        return Ok(false);
    }
    let Some(mut route) = LOCAL_ROUTE.get(&vault.store, wtxn, &root)? else {
        return Ok(false);
    };
    route.chosen = Some(LocalRouteChoice {
        ask: Some(seq),
        chosen_at: now,
    });
    LOCAL_ROUTE.put(&vault.store, wtxn, &root, &route)?;
    dispatcher.resume_budget_hold_in_txn(wtxn, root, &by.to_hex(), now)?;
    Ok(true)
}
