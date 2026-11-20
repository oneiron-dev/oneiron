//! The advance check's early ask (owner ruling RUN-BUDGET-SPENT = B, "you
//! can also check it in advance"; Engine ruling RUNBUDGET-ADVANCE-FLOW = A):
//! a root launch projected past the room its hard root scope has left asks
//! the owner, in the launch's own write, to add dollars before the run holds.

use super::*;

/// The root attempt an early ask is about; `None` for any other ask.
pub(super) fn asked_forecast(ask: &DecisionAsk) -> Option<AttemptId> {
    if ask.queue_pin.model != RUN_BUDGET_FORECAST_QUEUE {
        return None;
    }
    ask.correlation
        .and_then(|run| AttemptId::from_bytes(run.as_bytes()).ok())
}

/// The early ask about the run rooted at `root`, put to the owner role for
/// `principal`, stating `forecast` and `price`: keyed by the run.
fn forecast_request(
    root: AttemptId,
    principal: EntityId,
    forecast: &RunBudgetForecast,
    price: &FundsPrice,
) -> Result<HumanDecisionRequest> {
    let options = [RunBudgetChoice::AddFunds, RunBudgetChoice::StayParked]
        .iter()
        .map(|choice| choice.token().to_owned())
        .collect();
    let dollars = forecast
        .expected_usd_micros
        .map(|micros| format!(" (about {})", usd(micros)))
        .unwrap_or_default();
    // Fixed machine-lifecycle wording, as the hold's is.
    let text = format!(
        "This run is projected to need {} {}{dollars}, and {} are left under its cap. Add \
         dollars to its budget now, for good (at {}), or let it run and hold it at its cap as \
         usual?",
        forecast.expected_units,
        forecast.unit.as_str(),
        forecast.available_units,
        price.stated()
    );
    let question = RUN_BUDGET_SPENT.question(
        &[root.as_bytes().as_slice()],
        text,
        AnswerContract::Choice { options },
    )?;
    Ok(HumanDecisionRequest {
        question,
        principal,
        evidence: Vec::new(),
        reason: HumanAskReason::OwnerSelected,
        prior: None,
        prior_provider: None,
        queue_pin: ProviderPin {
            rung: DecisionRung::Human,
            model: RUN_BUDGET_FORECAST_QUEUE.to_owned(),
            version: RUN_BUDGET_FORECAST_QUEUE_VERSION.to_owned(),
        },
        to: AskTo::owner(),
        correlation: Some(EntityId::from_bytes(*root.as_bytes())?),
    })
}

/// Queues the early ask about the run rooted at `root`, in its root
/// launch's write, when `statement` projects the launch past the room its
/// hard root scope has left. That scope is the run's root scope
/// ([`run_root_scope_in_txn`]), read after the launch reserved the run's own
/// scope: under a pinned `budget`, the scope it pinned (review round 1 of
/// #8217); under a spend scope, the hard scope above the run's own. Asked
/// only when the vault has a live owner who may raise that scope (open,
/// hard, carved from no parent, paid by him or by no named payer) and the
/// vault's USD quote prices its unit; else the launch statement alone states
/// the shortfall, as before. A run whose own budget is carved from a spend
/// scope is bound by its carve, which is no owner's to raise: nothing is
/// asked (review round 2 of #8217). `None` when nothing is asked.
///
/// # Errors
///
/// Storage errors, or an ask the queue refuses.
pub(crate) fn queue_forecast_ask_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    root: AttemptId,
    statement: &super::super::LaunchStatement,
) -> Result<Option<u64>> {
    let Some(available_units) = statement.available_units else {
        return Ok(None);
    };
    if statement.expected.units <= available_units {
        return Ok(None);
    }
    let Some(principal) = crate::policy_model::owners_in_txn(vault, wtxn)?
        .into_iter()
        .next()
    else {
        return Ok(None);
    };
    let Some(scope) = run_root_scope_in_txn(vault, wtxn, root)? else {
        return Ok(None);
    };
    if !super::super::budget_trap_ask::scope_raisable_by(&scope, principal) {
        return Ok(None);
    }
    let Some(price) = funds_price_in_txn(vault, wtxn, &scope.unit) else {
        return Ok(None);
    };
    let forecast = RunBudgetForecast {
        scope: scope.scope,
        unit: scope.unit,
        expected_units: statement.expected.units,
        expected_usd_micros: statement.expected.expected_usd_micros,
        available_units,
        asked_at: vault.store.clock.now_recorded_at(),
    };
    let request = forecast_request(root, principal, &forecast, &price)?;
    FORECAST.put(&vault.store, wtxn, &root, &forecast)?;
    vault
        .queue_decision_ask_in_txn(wtxn, &request, None)
        .map(Some)
}

/// Withdraws the early ask about the run rooted at `root` while it is still
/// open, in the hold's write: the hold asks in its place.
pub(super) fn withdraw_forecast_ask_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    root: AttemptId,
) -> Result<()> {
    let correlation = Some(EntityId::from_bytes(*root.as_bytes())?);
    let open = vault
        .open_queue_asks_in_txn(wtxn, RUN_BUDGET_FORECAST_QUEUE)?
        .into_iter()
        .find(|ask| ask.correlation == correlation);
    if let Some(ask) = open {
        vault.withdraw_decision_ask_in_txn(wtxn, ask.seq)?;
    }
    Ok(())
}

/// The owner `by`'s `add_funds` answer to the early ask `seq` about the run
/// rooted at `root`, naming `amount_usd_micros`, in the answer's write: the
/// whole units it buys raise the hard root scope the launch projected
/// against, for good, and the amount is recorded under the run. The run is
/// not held, so nothing resumes. `false` when the owner may no longer raise
/// that scope.
pub(super) fn forecast_add_funds_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    root: AttemptId,
    by: EntityId,
    seq: u64,
    amount_usd_micros: u64,
) -> Result<bool> {
    let Some(forecast) = FORECAST.get(&vault.store, wtxn, &root)? else {
        return Ok(false);
    };
    let raisable = SCOPE
        .get(&vault.store, wtxn, &forecast.scope.0)?
        .is_some_and(|scope| super::super::budget_trap_ask::scope_raisable_by(&scope, by));
    if !raisable {
        return Ok(false);
    }
    let price = funds_price_in_txn(vault, wtxn, &forecast.unit)
        .ok_or_else(|| invalid("the run's budget unit has no USD price"))?;
    let units = funds_units(&price, amount_usd_micros)?;
    let now = vault.store.clock.now_recorded_at();
    super::super::budget_trap_ask::raise_scope_cap_in_txn(
        vault,
        wtxn,
        &forecast.scope,
        by,
        units,
        now.saturating_mul(1000),
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
    Ok(true)
}
