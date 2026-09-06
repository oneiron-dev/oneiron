//! Replay-first outbound effect execution.
//!
//! This module is the only production lane that may combine governance,
//! budget accounting, durable intent state, and transport.

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::connector_key::{
    self, ConnectorKeyStatus, EffectorBudgetCharge, EffectorBudgetChargeOutcome,
    EffectorBudgetOnExhaust,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::gate::{self, ExternalEffectGateInput, GateOutcome};
use crate::outbound_consent::{
    FrozenCallValidation, OutboundBindingAuthority, ScopedMcpCallContext,
};
use crate::outbound_intent_ledger::{
    BudgetChargeMarker, BudgetClass, FrozenOutboundCall, IntentDispatchResult, IntentEscalation,
    IntentEscalationReason, IntentId, IntentLedgerError, IntentState, OutboundCallClass,
    OutboundCallRequest, OutboundSendOutcome, RecordedOutboundOutcome, abandon_record,
    begin_definite_non_delivery_retry, complete_record, derive_intent_id, force_sync,
    hash_frozen_payload, insert_pending_in_txn, read_intent_record_in_txn,
    record_definite_non_delivery,
};

/// Pre-execution fan-out admission. It sits ahead of everything below: a
/// fan-out that is paused for judgment never reaches the gate, the ledger, or
/// transport. The peer-consult consumer calls it immediately before TASK
/// realization, so until that lands only this module's own tests drive it.
#[cfg_attr(not(test), allow(dead_code))]
mod fanout;

/// The fan-out admission contract other lanes bind to. `fanout` itself stays
/// private; these four are the pinned cross-lane surface.
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use fanout::{FanoutAutoDecider, FanoutAutoDisposition, FanoutEstimate, FanoutPlan};

pub(crate) type OutboundEffectError = IntentLedgerError;

/// Result of one replay-first effect execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OutboundEffectResult {
    pub(crate) dispatch: IntentDispatchResult,
    pub(crate) gate_decision_id: Option<String>,
    pub(crate) gate_outcome: Option<String>,
    pub(crate) gate_reason_codes: Vec<String>,
    pub(crate) gate_receipt_reasons: Vec<String>,
    pub(crate) budget_charge: Option<EffectorBudgetCharge>,
}

/// The only two commands accepted by the effectful entry.
#[allow(clippy::large_enum_variant)]
pub(crate) enum OutboundEffectCommand {
    New(PreparedEffect),
    Resume(IntentId),
}

/// Authorization material required only while admitting a new effect.
pub(crate) enum PreparedAuthorization {
    None,
    ScopedMcp {
        grant_id: EntityId,
        principal_ref: String,
        call: ScopedMcpCallContext,
    },
}

/// Fully frozen new-effect input. No transport object can change these axes.
pub(crate) struct PreparedEffect {
    pub(crate) attempt_id: AttemptId,
    pub(crate) call_seq: u64,
    pub(crate) server: String,
    pub(crate) tool: String,
    pub(crate) payload: Vec<u8>,
    pub(crate) idempotency_supported: bool,
    pub(crate) resolved_endpoint: Option<String>,
    pub(crate) gate: ExternalEffectGateInput,
    pub(crate) budget_class: BudgetClass,
    pub(crate) authorization: PreparedAuthorization,
    pub(crate) verified_actor: Option<(EntityId, EdgeActorClass)>,
}

impl PreparedEffect {
    fn payload_hash(&self) -> [u8; 32] {
        hash_frozen_payload(&self.payload)
    }

    fn intent_id(&self) -> Result<IntentId, IntentLedgerError> {
        derive_intent_id(
            self.attempt_id,
            self.call_seq,
            &self.server,
            &self.tool,
            &self.payload_hash(),
        )
    }
}

/// Connector-agnostic transport. The endpoint, bytes, and idempotency key are
/// readable only from the frozen call supplied here.
pub(crate) trait OutboundTransport {
    fn send(&mut self, call: &FrozenOutboundCall) -> OutboundSendOutcome;
}

/// The CA-05 send-hygiene headers this call must go out under, read from the
/// FROZEN bytes at the last boundary before transport.
///
/// Reading them here rather than re-deriving them is what makes retries
/// byte-identical: a replay never recomputes an unsubscribe target, it replays
/// the one the ledger froze. A payload that carries no hygiene headers — every
/// non-email send, and every connector payload that was never JSON — yields an
/// empty map, so nothing about existing transports changes.
///
/// # Errors
///
/// [`IntentLedgerError::InvalidRecord`] when the frozen payload carries the
/// hygiene field in a shape that cannot be replayed. A send whose headers the
/// ledger cannot vouch for does not reach the wire.
pub(crate) fn frozen_call_hygiene_headers(
    call: &FrozenOutboundCall,
) -> Result<std::collections::BTreeMap<String, String>, OutboundEffectError> {
    crate::campaign::send_hygiene::frozen_payload_hygiene_headers(call.payload()).map_err(|_| {
        IntentLedgerError::InvalidRecord("frozen outbound payload carries invalid hygiene headers")
    })
}

enum RecoveryGovernance {
    Allow,
    Block(&'static str),
    Revoke,
}

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

    let mut wtxn = vault.store.env.write_txn().map_err(Error::from)?;
    if let OutboundEffectCommand::New(prepared) = &command {
        if let Some((actor, actor_class)) = prepared.verified_actor {
            let entity_type = vault
                .get_entity_type_in_txn(&wtxn, &actor)?
                .ok_or(IntentLedgerError::InvalidBoundActor)?;
            crate::provenance::validate_actor_class(entity_type, actor_class)?;
        }
        verify_booking_effect(vault, &wtxn, &prepared.payload)?;
    }
    let record = read_intent_record_in_txn(vault, &wtxn, &intent_id)?;
    if let Some(record) = record {
        if let OutboundEffectCommand::New(prepared) = &command {
            validate_new_replay(&record, prepared)?;
        }
        drop(wtxn);
        force_sync(vault)?;
        return replay_record(vault, authority, record, now_ms, transport);
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

fn replay_record<T: OutboundTransport>(
    vault: &Vault,
    authority: &OutboundBindingAuthority,
    record: crate::outbound_intent_ledger::IntentLedgerRecord,
    now_ms: u64,
    transport: &mut T,
) -> Result<OutboundEffectResult, IntentLedgerError> {
    match (record.state, record.recorded_outcome) {
        (IntentState::Done, Some(RecordedOutboundOutcome::Acked)) => Ok(effect_result(
            &record,
            Some(OutboundSendOutcome::Acked),
            true,
            None,
        )),
        (IntentState::Abandoned, Some(RecordedOutboundOutcome::Abandoned(reason))) => {
            Ok(effect_result(&record, None, true, Some(reason)))
        }
        (IntentState::Pending, Some(RecordedOutboundOutcome::DefiniteNonDelivery)) => {
            send_pending(vault, authority, record, now_ms, true, transport)
        }
        (IntentState::Pending, None) if !record.idempotency_supported => {
            let abandoned = abandon_record(
                vault,
                record.id,
                IntentEscalationReason::NonIdempotentPending,
                now_ms,
            )?;
            Ok(effect_result(
                &abandoned,
                None,
                true,
                Some(IntentEscalationReason::NonIdempotentPending),
            ))
        }
        (IntentState::Pending, None) => {
            send_pending(vault, authority, record, now_ms, true, transport)
        }
        _ => Err(IntentLedgerError::InvalidRecord(
            "outbound state has no canonical recorded outcome",
        )),
    }
}

fn verify_booking_effect(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    bytes: &[u8],
) -> Result<(), IntentLedgerError> {
    crate::booking::emergency_reschedule::verify_frozen_effect_in(vault, txn, bytes).map_err(
        |error| {
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
        },
    )
}

fn send_pending<T: OutboundTransport>(
    vault: &Vault,
    authority: &OutboundBindingAuthority,
    record: crate::outbound_intent_ledger::IntentLedgerRecord,
    now_ms: u64,
    replayed: bool,
    transport: &mut T,
) -> Result<OutboundEffectResult, IntentLedgerError> {
    let call = FrozenOutboundCall::from_record(&record);
    if record.resolved_endpoint.is_some() && record.capability_provenance().is_none() {
        // Endpoint-bound rows are scoped rows. Never downgrade a reconstructed
        // one to ordinary governance when its typed discriminator is missing.
        let abandoned = abandon_record(
            vault,
            record.id,
            IntentEscalationReason::BindingInvalid,
            now_ms,
        )?;
        return Ok(effect_result(
            &abandoned,
            None,
            replayed,
            Some(IntentEscalationReason::BindingInvalid),
        ));
    }
    // Scoped capability rows must always pass the frozen grant/binding/server/
    // tool/endpoint check. Ordinary rows retain their existing endpoint-bound
    // validation behavior; connector text never opts a row into this branch.
    let requires_frozen_call_validation =
        record.capability_provenance().is_some() || record.resolved_endpoint.is_some();
    if requires_frozen_call_validation
        && !matches!(
            authority.validate_frozen_call_grant_for_recovery(vault, &call)?,
            FrozenCallValidation::Valid
        )
    {
        let abandoned = abandon_record(
            vault,
            record.id,
            IntentEscalationReason::BindingInvalid,
            now_ms,
        )?;
        return Ok(effect_result(
            &abandoned,
            None,
            replayed,
            Some(IntentEscalationReason::BindingInvalid),
        ));
    }

    match recovery_governance(vault, &record)? {
        RecoveryGovernance::Allow => {}
        RecoveryGovernance::Block(reason) => {
            let mut result = effect_result(&record, None, replayed, None);
            result.gate_receipt_reasons.push(reason.to_owned());
            return Ok(result);
        }
        RecoveryGovernance::Revoke => {
            let abandoned = abandon_record(
                vault,
                record.id,
                IntentEscalationReason::ConnectorRevoked,
                now_ms,
            )?;
            return Ok(effect_result(
                &abandoned,
                None,
                replayed,
                Some(IntentEscalationReason::ConnectorRevoked),
            ));
        }
    }

    // F2 is checked again at the last in-process boundary before transport.
    if requires_frozen_call_validation
        && !matches!(
            authority.validate_frozen_call_grant_for_recovery(vault, &call)?,
            FrozenCallValidation::Valid
        )
    {
        let abandoned = abandon_record(
            vault,
            record.id,
            IntentEscalationReason::BindingInvalid,
            now_ms,
        )?;
        return Ok(effect_result(
            &abandoned,
            None,
            replayed,
            Some(IntentEscalationReason::BindingInvalid),
        ));
    }

    // A definite non-delivery permits retry even without provider-native
    // idempotency. Clear that permit durably immediately before transport so a
    // crash after the wire may have started is once again Q4 Pending/uncertain.
    let record = if record.recorded_outcome == Some(RecordedOutboundOutcome::DefiniteNonDelivery) {
        begin_definite_non_delivery_retry(vault, record.id, now_ms)?
    } else {
        record
    };
    let call = FrozenOutboundCall::from_record(&record);
    {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        verify_booking_effect(vault, &txn, record.payload())?;
    }
    let outcome = transport.send(&call);
    match outcome {
        OutboundSendOutcome::Acked => {
            let done = complete_record(vault, record.id, now_ms)?;
            Ok(effect_result(&done, Some(outcome), replayed, None))
        }
        OutboundSendOutcome::Ambiguous if record.idempotency_supported => {
            Ok(effect_result(&record, Some(outcome), replayed, None))
        }
        OutboundSendOutcome::Ambiguous => {
            let abandoned = abandon_record(
                vault,
                record.id,
                IntentEscalationReason::NonIdempotentAmbiguous,
                now_ms,
            )?;
            Ok(effect_result(
                &abandoned,
                Some(outcome),
                replayed,
                Some(IntentEscalationReason::NonIdempotentAmbiguous),
            ))
        }
        OutboundSendOutcome::Failed(_) => {
            let retryable = record_definite_non_delivery(vault, record.id, now_ms)?;
            Ok(effect_result(&retryable, Some(outcome), replayed, None))
        }
    }
}

fn recovery_governance(
    vault: &Vault,
    record: &crate::outbound_intent_ledger::IntentLedgerRecord,
) -> Result<RecoveryGovernance, IntentLedgerError> {
    let Some(key_ref) = record.budget_accounting.key_ref.as_ref() else {
        return Ok(RecoveryGovernance::Allow);
    };
    let Some(key) = vault.get_connector_key(key_ref)? else {
        return Ok(RecoveryGovernance::Block("connector_key_unregistered"));
    };
    match key.status {
        ConnectorKeyStatus::Revoked => return Ok(RecoveryGovernance::Revoke),
        ConnectorKeyStatus::Pending => {
            return Ok(RecoveryGovernance::Block("connector_key_pending"));
        }
        ConnectorKeyStatus::Suspended => {
            return Ok(RecoveryGovernance::Block("connector_key_suspended"));
        }
        ConnectorKeyStatus::Active => {}
    }
    if let Some(charter) = key.charter.as_ref() {
        if connector_key::charter_block_drifted(charter)? {
            return Ok(RecoveryGovernance::Block("charter_drift"));
        }
        // Recovery must read the charter with the SAME identity the gate used,
        // or a per-grant deny at admission would replay as an allow here. That
        // identity is the row's DURABLE TYPED provenance — never its connector
        // text, which an ordinary connector can spell to look identical
        // (ONE-1885).
        let never_list_matches = match record.capability_provenance() {
            Some(capability) => {
                // The typed value must still describe the key this intent was
                // charged against. A mismatch means the capability this row was
                // authorized under is not the one registered here: fail closed
                // on the unregistered wall instead of silently continuing as an
                // ordinary connector.
                if capability.connector() != key.connector {
                    return Ok(RecoveryGovernance::Block("connector_key_unregistered"));
                }
                connector_key::charter_never_list_matches_capability(charter, capability)
                    || connector_key::charter_never_list_matches_scoped_channel(
                        charter,
                        &capability.ordinary_channel(),
                        &record.tool,
                    )
            }
            // No typed provenance: an ordinary connector, matched whole by the
            // ordinary rules only. No `never key` rule can reach it.
            None => {
                connector_key::charter_never_list_matches(charter, &key.connector, &record.tool)
            }
        };
        if never_list_matches {
            return Ok(RecoveryGovernance::Block("charter_never_list"));
        }
    }
    Ok(RecoveryGovernance::Allow)
}

fn validate_new_replay(
    record: &crate::outbound_intent_ledger::IntentLedgerRecord,
    prepared: &PreparedEffect,
) -> Result<(), IntentLedgerError> {
    if record.id != prepared.intent_id()?
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

fn effect_result(
    record: &crate::outbound_intent_ledger::IntentLedgerRecord,
    send_outcome: Option<OutboundSendOutcome>,
    replayed: bool,
    escalation_reason: Option<IntentEscalationReason>,
) -> OutboundEffectResult {
    OutboundEffectResult {
        dispatch: IntentDispatchResult {
            class: OutboundCallClass::Effectful,
            intent_id: Some(record.id),
            state: Some(record.state),
            send_outcome,
            replayed,
            escalation: escalation_reason.map(|reason| IntentEscalation {
                intent_id: Some(record.id),
                reason,
            }),
        },
        gate_decision_id: None,
        gate_outcome: None,
        gate_reason_codes: Vec::new(),
        gate_receipt_reasons: Vec::new(),
        budget_charge: None,
    }
}

fn gate_rejection(
    intent_id: IntentId,
    decision_id: crate::store::GateDecisionId,
    decision: gate::GateDecision,
) -> OutboundEffectResult {
    OutboundEffectResult {
        dispatch: IntentDispatchResult {
            class: OutboundCallClass::Effectful,
            intent_id: Some(intent_id),
            state: None,
            send_outcome: None,
            replayed: false,
            escalation: None,
        },
        gate_decision_id: Some(format!("gate:{}", decision_id.to_hex())),
        gate_outcome: Some(decision.outcome().as_str().to_owned()),
        gate_reason_codes: decision
            .reason_codes()
            .iter()
            .map(|reason| reason.as_str().to_owned())
            .collect(),
        gate_receipt_reasons: decision
            .receipt_reasons()
            .iter()
            .map(|reason| (*reason).to_owned())
            .collect(),
        budget_charge: None,
    }
}

#[cfg(test)]
mod tests;
