//! The two actor-bound effects one logical external mutation speaks for
//! (OF-427), moved here from `effect/mod.rs` with its budget preflight and
//! debit unchanged. FIX 6424 part 2a (Engine 10-20 21:0x) adds, per actor:
//! the press that actor's earlier admission of the same mutation spent is
//! reused on its retry (ruling 8); an Allow the other actor did not match
//! records no spend, so that actor's press still releases the mutation once
//! the other is answered (ruling 2); and the caller learns which actor held
//! it and which presses its admission spent.

use super::{
    ApprovalContext, charge_admitted_external_effect, evaluate_external_effect_policy,
    record_external_effect_policy,
};
use crate::connector_key;
use crate::error::Result;
use crate::gate::decision::{GateDecision, GateOutcome};
use crate::gate::input::ExternalEffectGateInput;
use crate::gate::resolution::PolicyManifestResolution;
use crate::outbound_intent_ledger::AdmittedApproval;
use crate::store::{GateDecisionId, Store};

/// What one admission of a two-actor mutation recorded: both actors'
/// decisions, scheduler first, the admitted decision when both allowed, and
/// the press each actor's recording spent.
pub(crate) struct PairAdmission {
    /// The scheduler's decision when both actors allowed and every budget
    /// had room; `None` when the mutation was not admitted.
    pub(crate) admitted: Option<GateDecisionId>,
    /// Each actor's recorded decision and its outcome.
    pub(crate) decisions: [(GateDecisionId, GateOutcome); 2],
    /// Each actor's press its admitted recording spent.
    pub(crate) spent_presses: [Option<crate::consent::EffectDigest>; 2],
}

/// Two actor-bound effects for one logical external mutation. Both live
/// grants and connector budgets must allow it. Budget keys are preflighted
/// together, then debited once per distinct key inside this one write txn;
/// an exhausted second key never consumes the first key's allowance.
/// `retries` holds each actor's press its earlier admission of this same
/// mutation spent, which its evaluation reuses.
pub(crate) fn check_external_effect_policy_pair(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    scheduler: &ExternalEffectGateInput,
    writer: &ExternalEffectGateInput,
    policy: &PolicyManifestResolution,
    new_effect: bool,
    retries: [Option<AdmittedApproval>; 2],
) -> Result<PairAdmission> {
    let context = |retry: Option<AdmittedApproval>| match retry {
        Some(proof) => ApprovalContext::Retry(proof),
        None if new_effect => ApprovalContext::FirstAdmission,
        None => ApprovalContext::Observe,
    };
    let mut host = evaluate_external_effect_policy(
        store,
        wtxn,
        scheduler,
        policy,
        None,
        None,
        context(retries[0]),
    )?;
    let mut authored = evaluate_external_effect_policy(
        store,
        wtxn,
        writer,
        policy,
        None,
        None,
        context(retries[1]),
    )?;
    if host.outcome() != GateOutcome::Allow || authored.outcome() != GateOutcome::Allow {
        host.release_unadmitted_press();
        authored.release_unadmitted_press();
        let host = record_external_effect_policy(store, wtxn, host)?;
        let authored = record_external_effect_policy(store, wtxn, authored)?;
        return Ok(held([host, authored]));
    }
    let same_key = matches!(
        (host.budget_target.as_ref(), authored.budget_target.as_ref()),
        (Some(a), Some(b)) if a.key_id == b.key_id
    );
    // Two per-grant keys of one catalog share its pool: the authored key
    // meets only its own rows, so the effect debits the pool once (ONE-1794).
    let shared_pool = !same_key
        && match (host.budget_target.as_ref(), authored.budget_target.as_ref()) {
            (Some(a), Some(b)) => connector_key::shares_budget_pool(store, wtxn, &a.key, &b.key)?,
            _ => false,
        };
    if new_effect {
        let now = crate::ports::recorded_at_in_txn(store, wtxn)?;
        for index in 0..2 {
            if index == 1 && same_key {
                continue;
            }
            let pool = !(index == 1 && shared_pool);
            let exhausted_preflight = {
                let governance = if index == 0 { &host } else { &authored };
                match governance.budget_target.as_ref() {
                    Some(target) => connector_key::preflight_effector_budgets_pooled(
                        store,
                        wtxn,
                        &target.key_id,
                        &target.key,
                        &target.governing_connector,
                        true,
                        now,
                        pool,
                    )?
                    .is_some(),
                    None => false,
                }
            };
            if exhausted_preflight {
                // The regular charger applies suspend-on-exhaust without
                // debiting an exhausted key. No other key has been charged.
                let denied = if index == 0 { &mut host } else { &mut authored };
                let (_, exhausted) =
                    charge_admitted_external_effect(store, wtxn, denied, true, pool)?;
                if !exhausted {
                    return Err(crate::error::Error::InvariantViolation(
                        "linear effect budget preflight diverged",
                    ));
                }
                denied.deny_budget_exhausted();
                host.release_unadmitted_press();
                authored.release_unadmitted_press();
                let host = record_external_effect_policy(store, wtxn, host)?;
                let authored = record_external_effect_policy(store, wtxn, authored)?;
                return Ok(held([host, authored]));
            }
        }
        for (index, governance) in [&mut host, &mut authored].into_iter().enumerate() {
            if index == 1 && same_key {
                continue;
            }
            let pool = !(index == 1 && shared_pool);
            let (_, exhausted) =
                charge_admitted_external_effect(store, wtxn, governance, true, pool)?;
            if exhausted {
                // Fail the transaction rather than persisting a partial debit.
                return Err(crate::error::Error::InvariantViolation(
                    "linear effect budget changed inside admission transaction",
                ));
            }
        }
    }
    let spent_presses = [host.spent_press_digest(), authored.spent_press_digest()];
    let (id, host_decision) = record_external_effect_policy(store, wtxn, host)?;
    let (writer_id, writer_decision) = record_external_effect_policy(store, wtxn, authored)?;
    Ok(PairAdmission {
        admitted: Some(id),
        decisions: [
            (id, host_decision.outcome()),
            (writer_id, writer_decision.outcome()),
        ],
        spent_presses,
    })
}

/// A mutation the pair did not admit: both decisions as recorded.
fn held(recorded: [(GateDecisionId, GateDecision); 2]) -> PairAdmission {
    let [(host_id, host), (writer_id, writer)] = recorded;
    PairAdmission {
        admitted: None,
        decisions: [(host_id, host.outcome()), (writer_id, writer.outcome())],
        spent_presses: [None, None],
    }
}
