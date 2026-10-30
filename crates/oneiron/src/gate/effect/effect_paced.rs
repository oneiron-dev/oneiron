//! A gate-direct execution check that paces (FIX 8686). An effect the Gate
//! allows whose every full budget row is a count-bound window that refuses
//! rather than suspends waits for that window, as the chokepoint's scoped
//! connector calls wait: nothing is recorded, charged or spent, and the
//! caller brings the effect back once the window opens. Any other outcome is
//! [`check_external_effect_policy`]'s own, admitting for execution.

use super::*;

/// What one gate-direct execution check came to.
pub(crate) enum ExternalEffectCheck {
    /// The recorded decision, and the charge its admission debited.
    Decided(GateDecisionId, GateDecision, Option<EffectorBudgetCharge>),
    /// The Gate allowed the effect and every full budget row it meets paces:
    /// no decision was recorded and nothing was charged or spent. The caller
    /// brings the effect back at `next_eligible_at`, Unix seconds on the
    /// engine's clock.
    Paced { next_eligible_at: u64 },
}

/// [`check_external_effect_policy`] admitting for execution, with a wait in
/// place of a budget-exhausted denial when every full row the governing key
/// and its catalog pool meet only paces. A Spend row and a row set to
/// suspend deny as before.
pub(crate) fn check_external_effect_policy_paced(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    effect: &ExternalEffectGateInput,
    policy: &PolicyManifestResolution,
) -> Result<ExternalEffectCheck> {
    let mut governance = evaluate_external_effect_policy(
        store,
        wtxn,
        effect,
        policy,
        None,
        None,
        ApprovalContext::FirstAdmission,
    )?;
    let send_like = effect.send_ref.is_some();
    let mut effector_charge = None;
    if governance.outcome() == GateOutcome::Allow {
        if let Some(target) = governance.budget_target.as_ref() {
            // The meter's own trusted clock, as the charge below reads it.
            let now = crate::ports::recorded_at_in_txn(store, wtxn)?;
            if let connector_key::BudgetBlock::Paced { next_eligible_at } =
                connector_key::budget_block_pooled(
                    store,
                    wtxn,
                    &target.key_id,
                    &target.key,
                    &target.governing_connector,
                    send_like,
                    now,
                    true,
                )?
            {
                return Ok(ExternalEffectCheck::Paced { next_eligible_at });
            }
        }
        let (charge, exhausted) =
            charge_admitted_external_effect(store, wtxn, &mut governance, send_like, true)?;
        if exhausted {
            governance.deny_budget_exhausted();
        }
        effector_charge = charge;
    }
    let (decision_id, decision) = record_external_effect_policy(store, wtxn, governance)?;
    Ok(ExternalEffectCheck::Decided(
        decision_id,
        decision,
        effector_charge,
    ))
}
