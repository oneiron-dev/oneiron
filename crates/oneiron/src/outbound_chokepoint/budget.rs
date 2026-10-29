//! The new-effect admission's budget steps, moved out of `admission.rs`
//! whole: the co-actor's preflight and the one-shot charge. FIX 8788 adds
//! the Linear mirror's Rate wait, and FIX 8686 the scoped connector call's:
//! a mutation whose only full budget rows are count-bound windows that
//! refuse rather than suspend is not denied, records no decision and charges
//! nothing, and comes back naming
//! [`crate::linear_sync::LINEAR_RATE_WINDOW_REASON`]. FIX 8689 adds the Spend
//! a preauthorizing row reserves before the call.

use super::types::OutboundEffectResult;
use crate::Vault;
use crate::connector_key::{
    self, ConnectorKeyStatus, ConnectorSpendBasis, ConnectorSpendEstimate, EffectorBudgetCharge,
    EffectorBudgetChargeOutcome, EffectorBudgetDebit, EffectorBudgetOnExhaust, SpendReserve,
};
use crate::error::Error;
use crate::gate::{self, GateOutcome};
use crate::outbound_intent_ledger::{
    BudgetChargeMarker, BudgetClass, IntentDispatchResult, IntentId, IntentLedgerError,
    OutboundCallClass,
};

/// FIX 8788, FIX 8686: when every full budget row a mutation meets only
/// paces, the instant (Unix seconds) its windows all open again: the
/// primary's key, and the co-actor's when it is another key (`co`, its own
/// rows alone unless `co_pool`), each read whole. A Linear mirror mutation
/// (it has a co-actor) and a scoped connector call ask; any other send
/// meets its budget as before.
pub(super) fn rate_paced(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    governance: &mut gate::ExternalEffectGovernance,
    co: Option<&mut gate::ExternalEffectGovernance>,
    budget_class: BudgetClass,
    co_pool: bool,
) -> Result<Option<u64>, IntentLedgerError> {
    let now = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
    let mut block = connector_key::BudgetBlock::Open;
    for (governance, pool) in [(Some(governance), true), (co, co_pool)] {
        let Some(target) = governance.and_then(gate::ExternalEffectGovernance::budget_target_mut)
        else {
            continue;
        };
        block = block.and(connector_key::budget_block_pooled(
            &vault.store,
            wtxn,
            &target.key_id,
            &target.key,
            &target.governing_connector,
            budget_class.is_send(),
            now,
            pool,
        )?);
    }
    Ok(match block {
        connector_key::BudgetBlock::Paced { next_eligible_at } => Some(next_eligible_at),
        connector_key::BudgetBlock::Open | connector_key::BudgetBlock::Hard => None,
    })
}

/// A mutation that waits for a full count-bound window (FIX 8788, FIX
/// 8686) until `next_eligible_at`: its grants allowed it, no decision is
/// recorded, nothing is charged and no ledger row is written, and it names
/// its reason. It was not delivered, and it asks no one for a press.
pub(super) fn rate_window_result(
    intent_id: IntentId,
    next_eligible_at: u64,
) -> OutboundEffectResult {
    OutboundEffectResult {
        resolution: None,
        dispatch: IntentDispatchResult {
            class: OutboundCallClass::Effectful,
            intent_id: Some(intent_id),
            state: None,
            send_outcome: None,
            replayed: false,
            escalation: None,
        },
        gate_decision_id: None,
        gate_outcome: Some(GateOutcome::Allow.as_str().to_owned()),
        gate_reason_codes: vec![crate::linear_sync::LINEAR_RATE_WINDOW_REASON.to_owned()],
        gate_receipt_reasons: Vec::new(),
        budget_charge: None,
        dedupe_suppressed: false,
        suppression_receipt: None,
        ceiling_count: None,
        approval_digest: None,
        approval_actor: None,
        paced_until: Some(next_eligible_at),
    }
}

/// FIX 8689: the price `tool` declares on the slate that governs the
/// primary's key, when a key governs the call and its slate names one.
pub(super) fn spend_price_in_txn(
    vault: &Vault,
    wtxn: &heed::RwTxn<'_>,
    governance: &mut gate::ExternalEffectGovernance,
    tool: &str,
) -> Result<Option<ConnectorSpendEstimate>, IntentLedgerError> {
    let Some(target) = governance.budget_target_mut() else {
        return Ok(None);
    };
    Ok(
        connector_key::governing_slate_in_txn(&vault.store, wtxn, &target.key)?
            .and_then(|(_, slate)| slate.tool(tool).and_then(|row| row.price.clone())),
    )
}

/// FIX 8689: what the primary key's preauthorizing Spend rows, and its
/// catalog pool's, say of `price`. `None` when one has no room: nothing
/// debited, and a row set to suspend suspended its key. `Some(None)` when
/// none preauthorizes. Otherwise the entries reserved (when `apply`) and
/// what they stood on.
pub(super) fn spend_reserve(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    governance: &mut gate::ExternalEffectGovernance,
    price: Option<&ConnectorSpendEstimate>,
    apply: bool,
) -> Result<Option<Option<(Vec<EffectorBudgetDebit>, ConnectorSpendBasis)>>, IntentLedgerError> {
    let Some(target) = governance.budget_target_mut() else {
        return Ok(Some(None));
    };
    // The meter's own trusted clock, as the charge reads it.
    let now = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
    Ok(
        match connector_key::reserve_connector_spend_in_txn(
            &vault.store,
            wtxn,
            &target.key_id,
            &target.key,
            &target.governing_connector,
            price,
            now,
            true,
            apply,
        )? {
            SpendReserve::SettleOnly => Some(None),
            SpendReserve::Reserved { debits, basis } => Some(Some((debits, basis))),
            SpendReserve::Exhausted { .. } => None,
        },
    )
}

/// OF-427: whether a co-actor's own (distinct) connector key is exhausted.
/// An exhausted key goes through the regular charger, which applies its
/// suspend-on-exhaust without debiting it, and the co-actor's decision turns
/// into a budget-exhausted denial. Nothing else has been charged yet.
pub(super) fn co_actor_exhausted(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    co: &mut gate::ExternalEffectGovernance,
    budget_class: BudgetClass,
    now_ms: u64,
    pool: bool,
) -> Result<bool, IntentLedgerError> {
    let Some(target) = co.budget_target_mut() else {
        return Ok(false);
    };
    let now = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
    if connector_key::preflight_effector_budgets_pooled(
        &vault.store,
        wtxn,
        &target.key_id,
        &target.key,
        &target.governing_connector,
        budget_class.is_send(),
        now,
        pool,
    )?
    .is_none()
    {
        return Ok(false);
    }
    let (_, _, exhausted) = charge_once(vault, wtxn, co, budget_class, now_ms, pool)?;
    if !exhausted {
        return Err(Error::InvariantViolation("co-actor budget preflight diverged").into());
    }
    co.deny_budget_exhausted();
    Ok(true)
}

pub(super) fn charge_once(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    governance: &mut gate::ExternalEffectGovernance,
    budget_class: BudgetClass,
    now_ms: u64,
    pool: bool,
) -> Result<(BudgetChargeMarker, Option<EffectorBudgetCharge>, bool), IntentLedgerError> {
    let mutation_recorded_at = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
    let Some(target) = governance.budget_target_mut() else {
        return Ok((
            BudgetChargeMarker {
                key_ref: None,
                budget_class,
                matched_rows: Vec::new(),
                sends_debit: 0,
                accounted_at_ms: now_ms,
            },
            None,
            false,
        ));
    };
    // Budget windows are enforcement state, so they advance on the engine's
    // trusted clock rather than a caller-supplied occurrence timestamp. This
    // also keeps the post-charge echo aligned with `effector_budget_read`.
    let budget_now = mutation_recorded_at;
    let outcome = connector_key::charge_effector_budgets_pooled(
        &vault.store,
        wtxn,
        &target.key_id,
        &mut target.key,
        &target.governing_connector,
        budget_class.is_send(),
        budget_now,
        pool,
    )?;
    let (mut charge, exhausted) = match outcome {
        EffectorBudgetChargeOutcome::NoRows(charge)
        | EffectorBudgetChargeOutcome::Charged(charge) => (charge, false),
        EffectorBudgetChargeOutcome::Exhausted {
            location,
            on_exhaust,
            mut charge,
        } => {
            if on_exhaust == EffectorBudgetOnExhaust::Suspend {
                connector_key::suspend_connector_key_in_txn(
                    &vault.store,
                    wtxn,
                    &target.key_id,
                    &target.key,
                    connector_key::budget_exhausted_reason(&location),
                    now_ms,
                )?;
                charge.read.status = ConnectorKeyStatus::Suspended;
            }
            (charge, true)
        }
    };
    charge.matched_rows.sort_unstable();
    charge.matched_rows.dedup();
    let marker = BudgetChargeMarker {
        key_ref: Some(charge.key_ref),
        budget_class,
        matched_rows: charge.matched_rows.clone(),
        sends_debit: charge.sends_debit,
        accounted_at_ms: now_ms,
    };
    Ok((marker, Some(charge), exhausted))
}
