//! Replay/send path: ledger-state dispatch, recovery governance, live-retry gate, transport outcomes.

use super::admission::{enforce_step_failure_policy, verify_booking_effect};
use super::types::{
    OutboundEffectResult, OutboundTransport, PreparedAuthorization, PreparedEffect,
};
use crate::Vault;
use crate::connector_key::{self, ConnectorKeyStatus, SlateDisposition};
use crate::consent::EffectDigest;
use crate::error::Error;
use crate::gate::{self, GateOutcome};
use crate::outbound::validate_publisher_signature_in_txn;
use crate::outbound_consent::{FrozenCallValidation, OutboundBindingAuthority};
use crate::outbound_intent_ledger::{
    FrozenOutboundCall, IntentDispatchResult, IntentEscalation, IntentEscalationReason, IntentId,
    IntentLedgerError, IntentState, OutboundCallClass, OutboundSendOutcome,
    RecordedOutboundOutcome, abandon_record, begin_definite_non_delivery_retry,
    complete_record_bridged, record_definite_non_delivery, record_possible_delivery,
};

pub(super) enum RecoveryGovernance {
    Allow,
    Block(&'static str),
    Revoke,
    /// FIX 990: the tool's setting is `always ask`; the send boundary
    /// releases it only on the owner's press on exactly this call.
    AlwaysAsk,
    /// FIX 990: the tool's setting is `never allow`; the request stops.
    NeverAllow,
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
        (
            IntentState::Abandoned,
            Some(RecordedOutboundOutcome::Abandoned(IntentEscalationReason::DedupeSuppressed)),
        ) => suppression_result(vault, &record, true),
        (IntentState::Abandoned, Some(RecordedOutboundOutcome::Abandoned(reason))) => {
            Ok(effect_result(&record, None, true, Some(reason)))
        }
        (IntentState::Pending, Some(RecordedOutboundOutcome::DefiniteNonDelivery)) => {
            send_pending_with_gate(
                vault, authority, record, prepared, None, now_ms, true, transport,
            )
        }
        (IntentState::Pending, None) if !record.idempotency_supported => {
            // A previous node may have sent before crashing. The stop reason
            // does not carry this delivery fact; store it independently.
            record_possible_delivery(vault, record.id)?;
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
            // A refused resume writes nothing. The row stays outcome-free
            // Pending, which already resolves as unresolved delivery.
            {
                let txn = vault.store.env.read_txn().map_err(Error::from)?;
                verify_booking_effect(vault, &txn, record.attempt_id, record.payload())?;
            }
            // This row was committed before a prior transport attempt. A crash
            // could have hidden a delivered response; persist that possibility
            // BEFORE a resumed no-wire failure can replace its retry marker.
            let uncertain = record_possible_delivery(vault, record.id)?;
            send_pending_with_gate(
                vault, authority, uncertain, prepared, None, now_ms, true, transport,
            )
        }
        _ => Err(IntentLedgerError::InvalidRecord(
            "outbound state has no canonical recorded outcome",
        )),
    }
}

#[cfg(test)]
pub(super) fn send_pending<T: OutboundTransport>(
    vault: &Vault,
    authority: &OutboundBindingAuthority,
    record: crate::outbound_intent_ledger::IntentLedgerRecord,
    now_ms: u64,
    replayed: bool,
    transport: &mut T,
) -> Result<OutboundEffectResult, IntentLedgerError> {
    send_pending_with_gate(
        vault, authority, record, None, None, now_ms, replayed, transport,
    )
}

/// The first send of the row its admission just committed. `pass_proof` is
/// the owner's press that admission's Gate spent on it, if it spent one: it
/// releases this send under `always ask` even when its kept copy did not
/// write (FIX 990).
pub(super) fn send_admitted<T: OutboundTransport>(
    vault: &Vault,
    authority: &OutboundBindingAuthority,
    record: crate::outbound_intent_ledger::IntentLedgerRecord,
    pass_proof: Option<EffectDigest>,
    now_ms: u64,
    transport: &mut T,
) -> Result<OutboundEffectResult, IntentLedgerError> {
    send_pending_with_gate(
        vault, authority, record, None, pass_proof, now_ms, false, transport,
    )
}

#[expect(clippy::too_many_arguments)]
fn send_pending_with_gate<T: OutboundTransport>(
    vault: &Vault,
    authority: &OutboundBindingAuthority,
    record: crate::outbound_intent_ledger::IntentLedgerRecord,
    prepared: Option<&PreparedEffect>,
    pass_proof: Option<EffectDigest>,
    now_ms: u64,
    replayed: bool,
    transport: &mut T,
) -> Result<OutboundEffectResult, IntentLedgerError> {
    let call = FrozenOutboundCall::from_record(&record);
    if record.resolved_endpoint.is_some() && record.capability_provenance().is_none() {
        // Endpoint-bound rows are scoped rows. Never downgrade a reconstructed
        // one to ordinary governance when its typed discriminator is missing.
        let reason = IntentEscalationReason::BindingInvalid;
        let abandoned = abandon_record(vault, record.id, reason, now_ms)?;
        return Ok(effect_result(&abandoned, None, replayed, Some(reason)));
    }
    // Scoped capability rows must always pass the frozen grant/binding/server/
    // tool/endpoint check. Ordinary rows retain their existing endpoint-bound
    // validation behavior; connector text never opts a row into this branch.
    let requires_frozen_call_validation =
        record.capability_provenance().is_some() || record.resolved_endpoint.is_some();
    if requires_frozen_call_validation
        && !matches!(
            authority.validate_frozen_call_grant(vault, &call)?,
            FrozenCallValidation::Valid
        )
    {
        let reason = IntentEscalationReason::BindingInvalid;
        let abandoned = abandon_record(vault, record.id, reason, now_ms)?;
        return Ok(effect_result(&abandoned, None, replayed, Some(reason)));
    }

    match recovery_governance(vault, &record)? {
        // `always ask` is judged at the send boundary below, after the live
        // retry's Gate.
        RecoveryGovernance::Allow | RecoveryGovernance::AlwaysAsk => {}
        RecoveryGovernance::NeverAllow => {
            let reason = IntentEscalationReason::ConnectorSlateNeverAllow;
            let abandoned = abandon_record(vault, record.id, reason, now_ms)?;
            return Ok(effect_result(&abandoned, None, replayed, Some(reason)));
        }
        RecoveryGovernance::Block(reason) => {
            let mut result = effect_result(&record, None, replayed, None);
            result.gate_receipt_reasons.push(reason.to_owned());
            return Ok(result);
        }
        RecoveryGovernance::Revoke => {
            let reason = IntentEscalationReason::ConnectorRevoked;
            let abandoned = abandon_record(vault, record.id, reason, now_ms)?;
            return Ok(effect_result(&abandoned, None, replayed, Some(reason)));
        }
    }

    // A typed mail approval is valid only with the exact current Gate input.
    // Hostless Resume has no such context: keep Pending instead of sending on
    // yesterday's consent. Terminal dedup returned before this branch. An
    // e-sign row's recorded press (FIX 6362) resumes as its sends always did.
    if replayed
        && prepared.is_none()
        && record.admitted_approval.is_some()
        && record.server == "email"
    {
        let mut held = effect_result(&record, None, replayed, None);
        held.gate_outcome = Some("pending".into());
        held.gate_receipt_reasons
            .push("mail_retry_requires_live_context".into());
        return Ok(held);
    }
    // A live retry keeps its frozen identity and paid admission, but today's
    // policy/authorization may still stop a Pending send. Do not charge, spend
    // approval, or record a second Allow. Terminal dedup never reaches here.
    if let Some(prepared) = prepared {
        let mut wtxn = vault.store.env.write_txn()?;
        let policy = gate::resolve_policy_manifest(&vault.store, &wtxn)?;
        enforce_step_failure_policy(
            vault,
            &wtxn,
            &policy,
            &prepared.payload,
            prepared.gate.provenance.actor_entity_ref,
        )?;
        // OF-420: a publisher signature retries only while its custody still
        // lets those exact bytes leave, with both participation switches on.
        if let PreparedAuthorization::PublisherSignature(signature) = &prepared.authorization {
            validate_publisher_signature_in_txn(vault, &wtxn, signature, prepared)?;
        }
        let invite = super::admission::calendar_admission_in_txn(vault, &wtxn, prepared)?;
        let required_grant_id = invite
            .as_ref()
            .and_then(crate::calendar::CalendarInviteAdmission::page_grant)
            .or_else(|| super::admission::required_grant_id(&prepared.authorization));
        let posting_gate =
            vault.space_posting_gate_in_txn(&wtxn, &prepared.payload, &prepared.gate)?;
        // FIX 6424 part 2a: or the press a pinned family kept for this row.
        let retry = record.admitted_approval.or_else(|| {
            crate::outbound_intent_ledger::pinned_retry_approval(
                vault,
                &wtxn,
                record.id,
                &prepared.gate,
            )
        });
        let governance = gate::evaluate_external_effect_policy(
            &vault.store,
            &mut wtxn,
            &posting_gate,
            &policy,
            required_grant_id,
            match &prepared.authorization {
                PreparedAuthorization::ScopedMcp { prepared, .. } => Some(prepared),
                PreparedAuthorization::None | PreparedAuthorization::PublisherSignature(_) => None,
            },
            retry.map_or(gate::ApprovalContext::Observe, gate::ApprovalContext::Retry),
        )?;
        if governance.outcome() != GateOutcome::Allow {
            let (decision_id, decision) =
                gate::record_external_effect_policy(&vault.store, &mut wtxn, governance)?;
            wtxn.commit().map_err(Error::from)?;
            let mut result =
                gate_rejection(record.id, decision_id, decision).held_by(&posting_gate);
            result.dispatch.state = Some(record.state);
            result.dispatch.replayed = replayed;
            return Ok(result);
        }
        // Governance lets this Pending send out; only now does an aged
        // admission meet its ceiling, under this same writer lock.
        if let Some(mut held) =
            super::admission::aged_admission_ceiling(vault, wtxn, prepared, &record, now_ms)?
        {
            held.dispatch.replayed = replayed;
            return Ok(held);
        }
    } else if crate::llm::StepEffectBinding::from_frozen_payload(record.payload())?.is_some() {
        // Engine-owned Resume has no PreparedEffect. Its frozen step identity
        // still rechecks the resident restriction before a Pending live send.
        let txn = vault.store.env.write_txn()?;
        let policy = gate::resolve_policy_manifest(&vault.store, &txn)?;
        let frozen: serde_json::Value = serde_json::from_slice(record.payload())
            .map_err(|_| IntentLedgerError::InvalidRecord("invalid frozen outbound payload"))?;
        let actor_hex = frozen
            .get("actor_entity_ref")
            .and_then(serde_json::Value::as_str)
            .ok_or(IntentLedgerError::InvalidRecord(
                "step effect actor missing",
            ))?;
        let actor = crate::entity_id::EntityId::from_hex(actor_hex)
            .map_err(|_| IntentLedgerError::InvalidRecord("step effect actor invalid"))?;
        enforce_step_failure_policy(vault, &txn, &policy, record.payload(), Some(actor))?;
    }

    // F2 is checked again at the last in-process boundary before transport.
    if requires_frozen_call_validation
        && !matches!(
            authority.validate_frozen_call_grant(vault, &call)?,
            FrozenCallValidation::Valid
        )
    {
        let reason = IntentEscalationReason::BindingInvalid;
        let abandoned = abandon_record(vault, record.id, reason, now_ms)?;
        return Ok(effect_result(&abandoned, None, replayed, Some(reason)));
    }

    {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        if !vault.frozen_space_posting_ready_in_txn(&txn, record.payload())? {
            let mut result = effect_result(&record, None, replayed, None);
            result.gate_outcome = Some("pending".to_owned());
            result
                .gate_receipt_reasons
                .push("space_posting_consent_required".to_owned());
            return Ok(result);
        }
    }
    // FIX 990: the last snapshot of the key, manifest, tool setting and
    // charters before the retry permit, the dedupe touch and the send.
    if let Some(stop) =
        super::connector_slate::send_boundary(vault, &record, pass_proof, now_ms, replayed)?
    {
        return Ok(stop);
    }

    // A definite non-delivery permits retry even without provider-native
    // idempotency. Clear that permit durably immediately before transport so a
    // crash after the wire may have started is once again Q4 Pending/uncertain.
    let record = if record.recorded_outcome == Some(RecordedOutboundOutcome::DefiniteNonDelivery) {
        let claimed = begin_definite_non_delivery_retry(vault, record.id, now_ms)?;
        if claimed.state == IntentState::Abandoned {
            return Ok(effect_result(
                &claimed,
                None,
                replayed,
                Some(IntentEscalationReason::DedupeReservationReplaced),
            ));
        }
        claimed
    } else {
        record
    };
    let call = FrozenOutboundCall::from_record(&record);
    {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        verify_booking_effect(vault, &txn, record.attempt_id, record.payload())?;
    }
    super::dedupe::touch_inflight(vault, &record.id)?;
    // Only measured as a live wait for a supervisor's SLIM status; the send
    // itself is unchanged.
    let outcome = vault.during_admitted_effect_send(&record, || transport.send(&call));
    vault.resume_from_slim_on_inbound()?;
    match outcome {
        OutboundSendOutcome::Acked => {
            // A turn program's send settles its step in the Done commit,
            // with the body its transport returned (DOOR-141 PR2); any
            // other send writes nothing more, and nothing here fails it.
            let body = transport.settled_result();
            let done = complete_record_bridged(vault, record.id, now_ms, |wtxn, done| {
                crate::dreamer_runner::settle_program_outbound_in_txn(
                    vault,
                    wtxn,
                    done,
                    body,
                    now_ms / 1_000,
                );
            })?;
            Ok(effect_result(&done, Some(outcome), replayed, None))
        }
        OutboundSendOutcome::Ambiguous if record.idempotency_supported => {
            let uncertain = record_possible_delivery(vault, record.id)?;
            Ok(effect_result(&uncertain, Some(outcome), replayed, None))
        }
        OutboundSendOutcome::Ambiguous => {
            record_possible_delivery(vault, record.id)?;
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
    // The key, the catalog charter and the tool's setting, one snapshot.
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    let Some(key) = connector_key::read_key_for_pack_in_txn(vault, &txn, key_ref)? else {
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
    // A typed capability can never be charged to a different connector,
    // regardless of whether that ordinary key has an approved manifest.
    if record
        .capability_provenance()
        .is_some_and(|capability| capability.connector() != key.connector)
    {
        return Ok(RecoveryGovernance::Block("connector_key_unregistered"));
    }
    // Compare the frozen snapshot before per-tool drift classification. An
    // approved removal/rename makes the tool unknown to the new manifest, but
    // the prior row must report the stale snapshot and the new manifest hash,
    // not hide that actionable fact behind generic tool drift.
    if record.capability_provenance().is_some()
        && let Some(manifest) = key.retained_manifest.as_ref()
    {
        let frozen = crate::outbound_consent::tool_call::frozen_manifest_binding(record.payload())?;
        let current_hash = manifest.hash()?;
        if frozen.is_none_or(|binding| {
            binding.key_ref != key_ref.to_hex()
                || current_hash != binding.manifest_hash
                || Some(binding.protocol_revision.as_str()) != key.protocol_revision.as_deref()
        }) {
            return Ok(RecoveryGovernance::Block("connector_manifest_stale"));
        }
    }
    if key.tool_requires_confirmation(&record.tool)
        || (record.capability_provenance().is_some() && key.retained_manifest.is_none())
    {
        return Ok(RecoveryGovernance::Block("connector_manifest_drift"));
    }
    // A per-grant key's call meets its catalog connector's charter too, as
    // the gate read it at admission.
    let catalog_charter = connector_key::catalog_charter_in_txn(&vault.store, &txn, &key)?;
    for charter in key.charter.iter().chain(catalog_charter.iter()) {
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
    // FIX 990: a scoped call meets its tool's setting now, as the Gate met
    // it at admission (a per-grant key's catalog slate included).
    if record.capability_provenance().is_some() {
        match connector_key::connector_tool_setting_in_txn(
            &vault.store,
            &txn,
            key_ref,
            &key,
            &record.tool,
        )? {
            SlateDisposition::NeverAllow => return Ok(RecoveryGovernance::NeverAllow),
            SlateDisposition::AlwaysAsk => return Ok(RecoveryGovernance::AlwaysAsk),
            SlateDisposition::Auto | SlateDisposition::AlwaysAllow => {}
        }
    }
    Ok(RecoveryGovernance::Allow)
}

pub(super) fn effect_result(
    record: &crate::outbound_intent_ledger::IntentLedgerRecord,
    send_outcome: Option<OutboundSendOutcome>,
    replayed: bool,
    escalation_reason: Option<IntentEscalationReason>,
) -> OutboundEffectResult {
    OutboundEffectResult {
        resolution: Some(
            crate::outbound_intent_ledger::IntentResolution::from_record(record)
                .expect("validated outbound intent has a resolution"),
        ),
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
        dedupe_suppressed: false,
        suppression_receipt: None,
        ceiling_count: None,
        approval_digest: None,
        approval_actor: None,
    }
}

pub(super) fn gate_rejection(
    intent_id: IntentId,
    decision_id: crate::store::GateDecisionId,
    decision: gate::GateDecision,
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
        dedupe_suppressed: false,
        suppression_receipt: None,
        ceiling_count: None,
        approval_digest: None,
        approval_actor: None,
    }
}

/// A suppressed attempt is terminal without a channel send. Its replicated
/// receipt must still be present on replay; absence is corruption, not a new
/// chance to spend approval or touch transport.
pub(super) fn suppression_result(
    vault: &Vault,
    record: &crate::outbound_intent_ledger::IntentLedgerRecord,
    replayed: bool,
) -> Result<OutboundEffectResult, IntentLedgerError> {
    let receipt = crate::receipt::suppression_for_intent(vault, &record.id)?;
    let mut result = effect_result(record, None, replayed, None);
    result.gate_outcome = Some("allow".to_owned());
    result.gate_reason_codes.push("gate.allow".to_owned());
    result.dedupe_suppressed = true;
    result.suppression_receipt = Some(receipt);
    Ok(result)
}
