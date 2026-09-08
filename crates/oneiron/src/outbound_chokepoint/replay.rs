//! Replay/send path: ledger-state dispatch, recovery governance, live-retry gate, transport outcomes.

use super::admission::verify_booking_effect;
use super::types::{
    OutboundEffectResult, OutboundTransport, PreparedAuthorization, PreparedEffect,
};
use crate::Vault;
use crate::connector_key::{self, ConnectorKeyStatus};
use crate::error::Error;
use crate::gate::{self, GateOutcome};
use crate::outbound_consent::{FrozenCallValidation, OutboundBindingAuthority};
use crate::outbound_intent_ledger::{
    FrozenOutboundCall, IntentDispatchResult, IntentEscalation, IntentEscalationReason, IntentId,
    IntentLedgerError, IntentState, OutboundCallClass, OutboundSendOutcome,
    RecordedOutboundOutcome, abandon_record, begin_definite_non_delivery_retry, complete_record,
    record_definite_non_delivery,
};

pub(super) enum RecoveryGovernance {
    Allow,
    Block(&'static str),
    Revoke,
}

pub(super) fn replay_record<T: OutboundTransport>(
    vault: &Vault,
    authority: &OutboundBindingAuthority,
    record: crate::outbound_intent_ledger::IntentLedgerRecord,
    prepared: Option<&PreparedEffect>,
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
            send_pending_with_gate(vault, authority, record, prepared, now_ms, true, transport)
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
            send_pending_with_gate(vault, authority, record, prepared, now_ms, true, transport)
        }
        _ => Err(IntentLedgerError::InvalidRecord(
            "outbound state has no canonical recorded outcome",
        )),
    }
}

pub(super) fn send_pending<T: OutboundTransport>(
    vault: &Vault,
    authority: &OutboundBindingAuthority,
    record: crate::outbound_intent_ledger::IntentLedgerRecord,
    now_ms: u64,
    replayed: bool,
    transport: &mut T,
) -> Result<OutboundEffectResult, IntentLedgerError> {
    send_pending_with_gate(vault, authority, record, None, now_ms, replayed, transport)
}

fn send_pending_with_gate<T: OutboundTransport>(
    vault: &Vault,
    authority: &OutboundBindingAuthority,
    record: crate::outbound_intent_ledger::IntentLedgerRecord,
    prepared: Option<&PreparedEffect>,
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

    // A live retry keeps its frozen identity and paid admission, but today's
    // policy/authorization may still stop a Pending send. Do not charge, spend
    // approval, or record a second Allow. Terminal dedup never reaches here.
    if let Some(prepared) = prepared {
        let mut wtxn = vault.store.env.write_txn().map_err(Error::from)?;
        let policy = gate::resolve_policy_manifest(&vault.store, &wtxn)?;
        let required_grant_id = match &prepared.authorization {
            PreparedAuthorization::None => None,
            PreparedAuthorization::ScopedMcp { grant_id, .. } => Some(*grant_id),
        };
        let governance = gate::evaluate_external_effect_policy(
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
            let mut result = gate_rejection(record.id, decision_id, decision);
            result.dispatch.state = Some(record.state);
            result.dispatch.replayed = replayed;
            return Ok(result);
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
        verify_booking_effect(vault, &txn, record.attempt_id, record.payload())?;
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

pub(super) fn recovery_governance(
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

pub(super) fn gate_rejection(
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
