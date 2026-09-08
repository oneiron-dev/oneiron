//! New-effect admission path: actor/booking/calendar checks, gate eval, one-shot budget debit, Pending insert.

use super::replay::{gate_rejection, replay_record, send_pending};
#[cfg(test)]
use super::types::BEFORE_NEW_ADMISSION;
use super::types::{
    OutboundEffectCommand, OutboundEffectError, OutboundEffectResult, OutboundTransport,
    PreparedAuthorization, PreparedEffect,
};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::connector_key::{
    self, ConnectorKeyStatus, EffectorBudgetCharge, EffectorBudgetChargeOutcome,
    EffectorBudgetOnExhaust,
};
use crate::error::Error;
use crate::gate::{self, GateOutcome};
use crate::outbound_consent::OutboundBindingAuthority;
use crate::outbound_intent_ledger::{
    BudgetChargeMarker, BudgetClass, IntentLedgerError, OutboundCallRequest, force_sync,
    insert_pending_in_txn, read_intent_for_attempt_in_txn, read_intent_record_in_txn,
};

/// Executes every outbound effect in ledger-read → replay → gate → debit →
/// durable-Pending → transport order.
pub(crate) fn execute_outbound_effect<T: OutboundTransport>(
    vault: &Vault,
    authority: &OutboundBindingAuthority,
    command: OutboundEffectCommand,
    now_ms: u64,
    transport: &mut T,
) -> Result<OutboundEffectResult, OutboundEffectError> {
    let intent_id = match &command {
        OutboundEffectCommand::New(prepared) => prepared.intent_id()?,
        OutboundEffectCommand::Resume(intent_id) => *intent_id,
    };

    #[cfg(test)]
    if matches!(&command, OutboundEffectCommand::New(_)) {
        BEFORE_NEW_ADMISSION.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
    }
    let mut wtxn = vault.store.env.write_txn().map_err(Error::from)?;
    if let OutboundEffectCommand::New(prepared) = &command {
        if let Some((actor, actor_class)) = prepared.verified_actor {
            let entity_type = vault
                .get_entity_type_in_txn(&wtxn, &actor)?
                .ok_or(IntentLedgerError::InvalidBoundActor)?;
            crate::provenance::validate_actor_class(entity_type, actor_class)?;
            if prepared.gate.provenance.actor_entity_ref != Some(actor)
                || prepared.gate.actor.actor_ref.as_deref() != Some(actor.to_hex().as_str())
                || prepared.gate.actor.actor_class != actor_class.gate_actor_class()
            {
                return Err(IntentLedgerError::InvalidBoundActor);
            }
        }
        verify_booking_effect(vault, &wtxn, prepared.attempt_id, &prepared.payload)?;
    }
    // Payload-derived ids alone are not unique logical calls. Resolve the
    // attempt under the SAME writer lock as the gate, debit, and Pending insert.
    let record = match &command {
        OutboundEffectCommand::New(prepared) => {
            read_intent_for_attempt_in_txn(vault, &wtxn, prepared.attempt_id, prepared.call_seq)?
        }
        OutboundEffectCommand::Resume(_) => read_intent_record_in_txn(vault, &wtxn, &intent_id)?,
    };
    if let Some(record) = record {
        if let OutboundEffectCommand::New(prepared) = &command {
            validate_new_replay(&record, prepared)?;
        }
        drop(wtxn);
        force_sync(vault)?;
        let prepared = match &command {
            OutboundEffectCommand::New(prepared) => Some(prepared),
            OutboundEffectCommand::Resume(_) => None,
        };
        return replay_record(vault, authority, record, prepared, now_ms, transport);
    }

    let OutboundEffectCommand::New(prepared) = command else {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound resume target is missing",
        ));
    };

    // CAL-04 (ONE-1786) verb wall. `calendar.invite` is the one verb whose
    // frozen bytes must carry a payload this lane can vouch for: C7's exact
    // five-field iMIP body. A call that claims the verb without one is a
    // hand-rolled draft reaching for the calendar connector past the invite
    // contract, so the last durable boundary refuses it instead of admitting a
    // send with no method, no UID, and no SEQUENCE.
    //
    // Recognition ONLY. The UID/SEQUENCE transition and the vault-only hygiene
    // evaluation already ran at the schedule chokepoint, atomically with the
    // attempt and TASK that produced this call; re-running either here would be
    // the second state transition per logical mutation the contract forbids,
    // and a connector retry replays this record without re-entering the branch
    // at all.
    if prepared.tool == crate::calendar::CALENDAR_INVITE_VERB
        && crate::calendar::decode_frozen_calendar_invite(&prepared.payload).is_err()
    {
        return Err(IntentLedgerError::InvalidInput(
            "calendar.invite requires its exact five-field frozen payload",
        ));
    }

    let policy = gate::resolve_policy_manifest(&vault.store, &wtxn)?;
    let required_grant_id = match &prepared.authorization {
        PreparedAuthorization::None => None,
        PreparedAuthorization::ScopedMcp { grant_id, .. } => Some(*grant_id),
    };
    let mut governance = gate::evaluate_external_effect_policy(
        &vault.store,
        &mut wtxn,
        &prepared.gate,
        &policy,
        required_grant_id,
    )?;
    if governance.outcome() != GateOutcome::Allow {
        let (decision_id, decision) =
            gate::record_external_effect_policy(&vault.store, &mut wtxn, governance)?;
        wtxn.commit().map_err(Error::from)?;
        return Ok(gate_rejection(intent_id, decision_id, decision));
    }

    let (budget_accounting, budget_charge, exhausted) = charge_once(
        vault,
        &mut wtxn,
        &mut governance,
        prepared.budget_class,
        now_ms,
    )?;
    if exhausted {
        governance.deny_budget_exhausted();
        let (decision_id, decision) =
            gate::record_external_effect_policy(&vault.store, &mut wtxn, governance)?;
        wtxn.commit().map_err(Error::from)?;
        let mut result = gate_rejection(intent_id, decision_id, decision);
        result.budget_charge = budget_charge;
        return Ok(result);
    }

    let payload_hash = prepared.payload_hash();
    // The gate's VERIFIED per-grant capability identity. It is the only
    // capability authority this admission may carry forward (ONE-1885).
    let gate_capability = governance.scoped_capability().cloned();
    let (authorization_binding, capability_provenance) = match &prepared.authorization {
        PreparedAuthorization::None => {
            if prepared.resolved_endpoint.is_some() {
                return Err(IntentLedgerError::InvalidInput(
                    "endpoint effect requires scoped authorization",
                ));
            }
            // An ordinary authorization path never carries capability
            // provenance, whatever its connector string happens to spell.
            (None, None)
        }
        PreparedAuthorization::ScopedMcp {
            grant_id,
            principal_ref,
            call,
        } => {
            let minted = authority.mint_scoped_binding_in_txn(
                vault,
                &wtxn,
                *grant_id,
                principal_ref,
                &intent_id,
                call,
                &payload_hash,
            )?;
            // Both readers of this admission — the gate's grant match and the
            // binding mint's own re-verification on this same write snapshot —
            // must have produced the SAME typed identity, or the authorization
            // is not one this engine can vouch for.
            match minted {
                Some((binding, capability)) if gate_capability.as_ref() == Some(&capability) => {
                    (Some(binding), Some(capability))
                }
                _ => {
                    return Err(IntentLedgerError::InvalidInput(
                        "scoped authorization changed during admission",
                    ));
                }
            }
        }
    };

    let mut request = OutboundCallRequest::new(
        prepared.attempt_id,
        prepared.call_seq,
        prepared.server,
        prepared.tool,
        prepared.payload,
        now_ms,
    );
    request.authorization_binding = authorization_binding;
    request.resolved_endpoint = prepared.resolved_endpoint;
    if let Some(capability) = capability_provenance {
        request = request.with_capability_provenance(capability);
    }
    let pending = crate::outbound_intent_ledger::IntentLedgerRecord::pending(
        request,
        prepared.idempotency_supported,
        budget_accounting,
    )?;
    if pending.id != intent_id {
        return Err(IntentLedgerError::InvalidRecord(
            "prepared outbound identity changed",
        ));
    }
    let (decision_id, decision) =
        gate::record_external_effect_policy(&vault.store, &mut wtxn, governance)?;
    insert_pending_in_txn(vault, &mut wtxn, &pending)?;
    wtxn.commit().map_err(Error::from)?;
    force_sync(vault)?;

    let mut result = send_pending(vault, authority, pending, now_ms, false, transport)?;
    result.gate_decision_id = Some(format!("gate:{}", decision_id.to_hex()));
    result.gate_outcome = Some(decision.outcome().as_str().to_owned());
    result.gate_reason_codes = decision
        .reason_codes()
        .iter()
        .map(|reason| reason.as_str().to_owned())
        .collect();
    result.gate_receipt_reasons = decision
        .receipt_reasons()
        .iter()
        .map(|reason| (*reason).to_owned())
        .collect();
    result.budget_charge = budget_charge;
    Ok(result)
}

fn charge_once(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    governance: &mut gate::ExternalEffectGovernance,
    budget_class: BudgetClass,
    now_ms: u64,
) -> Result<(BudgetChargeMarker, Option<EffectorBudgetCharge>, bool), IntentLedgerError> {
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
    let budget_now = crate::unix_seconds_now();
    let outcome = connector_key::charge_effector_budgets(
        &vault.store,
        wtxn,
        &target.key_id,
        &mut target.key,
        &target.governing_connector,
        budget_class.is_send(),
        budget_now,
    )?;
    let (mut charge, exhausted) = match outcome {
        EffectorBudgetChargeOutcome::NoRows(charge)
        | EffectorBudgetChargeOutcome::Charged(charge) => (charge, false),
        EffectorBudgetChargeOutcome::Exhausted {
            row_index,
            on_exhaust,
            mut charge,
        } => {
            if on_exhaust == EffectorBudgetOnExhaust::Suspend {
                connector_key::suspend_connector_key_in_txn(
                    &vault.store,
                    wtxn,
                    &target.key_id,
                    &target.key,
                    connector_key::budget_exhausted_reason(row_index),
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

pub(super) fn verify_booking_effect(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
    bytes: &[u8],
) -> Result<(), IntentLedgerError> {
    crate::booking::emergency_reschedule::verify_frozen_effect_in(vault, txn, attempt, bytes)
        .map_err(|error| {
            let error = crate::memory::booking_error(error);
            if let Some(denial) = error.gate_denial_error() {
                return IntentLedgerError::Engine(denial);
            }
            if error.code == crate::memory::MEMORY_CODE_FORBIDDEN {
                IntentLedgerError::InvalidBoundActor
            } else {
                IntentLedgerError::InvalidInput(
                    "emergency effect authority or revision is no longer current",
                )
            }
        })
}

fn validate_new_replay(
    record: &crate::outbound_intent_ledger::IntentLedgerRecord,
    prepared: &PreparedEffect,
) -> Result<(), IntentLedgerError> {
    if record.id != prepared.intent_id()?
        || record.attempt_id != prepared.attempt_id
        || record.call_seq != prepared.call_seq
        || record.idempotency_supported != prepared.idempotency_supported
        || record.budget_accounting.budget_class != prepared.budget_class
        || record.server != prepared.server
        || record.tool != prepared.tool
        || record.payload_hash != prepared.payload_hash()
        || record.payload() != prepared.payload.as_slice()
        || record.resolved_endpoint != prepared.resolved_endpoint
    {
        return Err(IntentLedgerError::InvalidRecord(
            "new outbound replay does not match persisted intent",
        ));
    }
    Ok(())
}
