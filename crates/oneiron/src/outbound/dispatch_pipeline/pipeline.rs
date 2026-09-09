//! O2 resolve-gate-window-execute dispatch pipeline: dispatch, verified-actor dispatch, and the dispatch_inner spine.
use std::collections::BTreeMap;

use super::enrich_dispatch_channel_identity;
use super::frozen_payload::FrozenOutboundPayload;
use super::policy_risk::outbound_dispatch_policy_risk;
use super::retry_after::{PROVIDER_RETRY_AFTER_FIELD, provider_retry_after_secs};
use super::transport::DispatchChokepointTransport;
use crate::Vault;
use crate::campaign::send_hygiene::inject_campaign_email_hygiene_headers;
use crate::delivery_window::DeliveryWindowApnsInterruptionLevel;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::gate::{self, ExternalEffectGateInput, ExternalEffectPolicyRisk, GateOutcome};
use crate::linkedin_connector::LinkedInSeatPolicyAction;
use crate::outbound::OutboundDeliveryWindowDecision;
use crate::outbound::capability::{OutboundRetryClass, normalize_key, outbound_verb_contract};
use crate::outbound::dispatch_attempt_id::outbound_dispatch_attempt_id;
use crate::outbound::dispatch_types::{
    OutboundDispatchError, OutboundDispatchOutcome, OutboundDispatchRequest,
    OutboundDispatchResult, OutboundExecutionOutcomeKind, OutboundExecutionSink,
};
use crate::outbound::receipt_fields::{
    append_dispatch_outcome_receipt_fields, append_execution_receipt_fields,
    append_optional_receipt_field, append_window_receipt_fields,
    append_window_resolution_receipt_fields,
};
use crate::outbound::window_door::{
    outbound_delivery_window_decision_at_door, outbound_delivery_window_resolution_at_door,
};
use crate::outbound_intent_ledger::{IntentLedgerError, read_intent_for_attempt_in_txn};
use crate::receipt::outbound_intent_receipt;
/// Stateless O2 resolve -> gate -> window -> execute -> receipt pipeline.
#[derive(Clone, Copy, Debug, Default)]
pub struct OutboundDispatchPipeline;
impl OutboundDispatchPipeline {
    pub fn dispatch<S: OutboundExecutionSink>(
        self,
        vault: &Vault,
        request: OutboundDispatchRequest,
        sink: &mut S,
    ) -> std::result::Result<OutboundDispatchResult, OutboundDispatchError> {
        self.dispatch_inner(vault, request, sink, None)
    }

    /// Dispatches an outbound intent after validating the facade-bound actor
    /// in the exact gate-decision transaction. The general dispatch API stays
    /// available to engine-owned callers whose actor model is different.
    pub(in crate::outbound) fn dispatch_with_verified_actor<S: OutboundExecutionSink>(
        self,
        vault: &Vault,
        request: OutboundDispatchRequest,
        sink: &mut S,
        actor: EntityId,
        actor_class: EdgeActorClass,
    ) -> std::result::Result<OutboundDispatchResult, OutboundDispatchError> {
        self.dispatch_inner(vault, request, sink, Some((actor, actor_class)))
    }

    fn dispatch_inner<S: OutboundExecutionSink>(
        self,
        vault: &Vault,
        mut request: OutboundDispatchRequest,
        sink: &mut S,
        verified_actor: Option<(EntityId, EdgeActorClass)>,
    ) -> std::result::Result<OutboundDispatchResult, OutboundDispatchError> {
        // OF-326 talk-only (ONE-1546): an intent originating from a session
        // currently in off-record mode is rejected before verb resolution —
        // the typed error carries the exit-prompt semantics. Intents from a
        // session flipped back on-record dispatch normally, and the OF-333
        // floor below still classifies every real egress.
        if let Some(session_ref) = request.originating_session_ref.as_deref()
            && let Some(session) = vault.off_record_session(session_ref)?
            && session.mode == crate::off_record::OffRecordMode::OffRecord
        {
            return Err(OutboundDispatchError::Engine(Error::OffRecordTalkOnly {
                session_ref: session_ref.to_owned(),
            }));
        }

        let verb_contract = outbound_verb_contract(&request.intent.channel, &request.intent.verb)?;
        let idempotency_supported = !matches!(
            verb_contract.retry_class,
            OutboundRetryClass::NonIdempotentInterrupt
        );

        // Find the logical attempt BEFORE consulting today's sender set. A
        // stable ref is only a lookup key, never authority to replay a different
        // request. The exact frozen binding is checked below and again by New
        // at the chokepoint; Resume alone would skip that request check.
        let ledger_identity_ref = request
            .ledger_identity_ref
            .as_deref()
            .unwrap_or(&request.intent_ref);
        let attempt_id = outbound_dispatch_attempt_id(ledger_identity_ref)?;
        let replay = {
            let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
            read_intent_for_attempt_in_txn(vault, &rtxn, attempt_id, 0)?
        };
        let invalid_replay = || {
            OutboundDispatchError::Chokepoint(IntentLedgerError::InvalidRecord(
                "outbound dispatch replay does not match its admitted binding",
            ))
        };
        request.channel_identity_ref = if let Some(record) = replay.as_ref() {
            let frozen: serde_json::Value =
                serde_json::from_slice(record.payload()).map_err(|_| invalid_replay())?;
            let sender = match frozen.get("channel_identity_ref") {
                Some(serde_json::Value::Null) => None,
                Some(serde_json::Value::String(value)) => {
                    Some(EntityId::from_hex(value).map_err(|_| invalid_replay())?)
                }
                _ => return Err(invalid_replay()),
            };
            if request.channel_identity_ref.is_some() && request.channel_identity_ref != sender {
                return Err(invalid_replay());
            }
            sender
        } else {
            let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
            enrich_dispatch_channel_identity(
                &vault.store,
                &rtxn,
                &request.intent.channel,
                request.actor.actor_entity_ref.as_ref(),
                request.channel_identity_ref,
            )?
        };
        let policy_risk = outbound_dispatch_policy_risk(request.gate, verb_contract);
        // The live claims are read once, here, at execute time. No schedule-time
        // window verdict is persisted or replayed.
        let window_resolution =
            outbound_delivery_window_resolution_at_door(vault, &request, verb_contract)?;
        let window_decision =
            outbound_delivery_window_decision_at_door(&request, &window_resolution);
        // Carry the policy's effective APNs ceiling all the way to the sink;
        // receipts alone must never be the only enforcement surface.
        if let OutboundDeliveryWindowDecision::DeliverNowWithApnsCap { to, .. } = &window_decision {
            request.delivery_window_apns_interruption_level = match to.as_str() {
                "push:passive" => Some(DeliveryWindowApnsInterruptionLevel::Passive),
                "push:active" => Some(DeliveryWindowApnsInterruptionLevel::Active),
                "push:time_sensitive" => Some(DeliveryWindowApnsInterruptionLevel::TimeSensitive),
                "push:critical" => Some(DeliveryWindowApnsInterruptionLevel::Critical),
                _ => request.delivery_window_apns_interruption_level,
            };
        }
        let effect = ExternalEffectGateInput {
            actor: request.actor.gate_actor(),
            provenance: request.actor.provenance(),
            verb: verb_contract.kind.clone(),
            channel: request.intent.channel.clone(),
            channel_identity_ref: request.channel_identity_ref,
            counterparty: request
                .counterparty_ref
                .clone()
                .or_else(|| Some(request.intent.target.clone())),
            brief_ref: request.intent.job_ref.clone(),
            send_ref: Some(request.intent_ref.clone()),
            standing_grant_ref: None,
            scoped_mcp_call: None,
            counterparty_first_touch: None,
            counterparty_opted_out: false,
            counterparty_opt_out_receipt_reason: None,
            has_opted_in: request.gate.has_opted_in,
            has_permission: request.gate.has_permission,
            policy_risk,
        };

        // Budget debits must not outrun the pipeline: a dispatch the window
        // parks (Hold/Degrade/LetGo) or the seat policy stops never becomes
        // an effect, so it must not consume or exhaust a connector-key
        // budget — it debits when it re-enters and actually executes. Both
        // walls are decidable before the gate txn (the window decision is
        // already resolved; the seat policy is a pure evaluation), so the
        // debit stays atomic with the gate decision that releases execution.
        let window_admits = matches!(
            &window_decision,
            OutboundDeliveryWindowDecision::DeliverNow
                | OutboundDeliveryWindowDecision::DeliverNowWithApnsCap { .. }
        );
        let mut linkedin_decision = if window_admits {
            request.linkedin_sandbox_policy.as_ref().map(|policy| {
                policy.evaluate_outbound(
                    &request.intent.channel,
                    &verb_contract.kind,
                    request.occurred_at,
                )
            })
        } else {
            None
        };
        let admit_for_execution = window_admits
            && linkedin_decision
                .as_ref()
                .is_none_or(|decision| matches!(decision.action, LinkedInSeatPolicyAction::Allow));

        let payload = if admit_for_execution || replay.is_some() {
            let mut hygiene_headers = BTreeMap::new();
            inject_campaign_email_hygiene_headers(
                &normalize_key(&request.intent.channel),
                &mut hygiene_headers,
                request.campaign_unsubscribe.as_ref(),
            )?;
            let payload = serde_json::to_vec(&FrozenOutboundPayload {
                intent: &request.intent,
                hygiene_headers,
                calendar_invite: request.calendar_invite.as_ref(),
                actor_class: &request.actor.actor_class,
                actor_ref: request.actor.actor_ref.as_deref(),
                actor_entity_ref: request.actor.actor_entity_ref.map(|id| id.to_hex()),
                channel_identity_ref: request.channel_identity_ref.map(|id| id.to_hex()),
                counterparty_ref: request.counterparty_ref.as_deref(),
                has_opted_in: request.gate.has_opted_in,
                has_permission: request.gate.has_permission,
                requested_policy_risk: request.gate.policy_risk.to_gate().as_str(),
                policy_risk: policy_risk.as_str(),
                originating_session_ref: request.originating_session_ref.as_deref(),
            })
            .map_err(|_| Error::InvariantViolation("outbound intent freeze failed"))?;
            if let Some(record) = replay.as_ref() {
                if record.server != request.intent.channel
                    || record.tool != verb_contract.kind
                    || record.payload() != payload.as_slice()
                    || record.idempotency_supported != idempotency_supported
                    || !record.budget_accounting.budget_class.is_send()
                    || record.resolved_endpoint.is_some()
                    || record.authorization_binding.is_some()
                    || record.capability_provenance().is_some()
                {
                    return Err(invalid_replay());
                }
                // New validates this only at admission. A facade retry must still
                // name its bound actor, not borrow the original actor's authority.
                if let Some((actor, actor_class)) = verified_actor {
                    let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
                    let entity_type = vault
                        .get_entity_type_in_txn(&rtxn, &actor)?
                        .ok_or(OutboundDispatchError::InvalidBoundActor)?;
                    crate::provenance::validate_actor_class(entity_type, actor_class)?;
                    if request.actor.actor_entity_ref != Some(actor)
                        || request.actor.actor_ref.as_deref() != Some(actor.to_hex().as_str())
                        || request.actor.actor_class != actor_class.gate_actor_class()
                    {
                        return Err(OutboundDispatchError::InvalidBoundActor);
                    }
                }
            }
            Some(payload)
        } else {
            None
        };

        let mut engine_receipt_fields = BTreeMap::new();
        let mut engine_policy_trace = Vec::new();
        let linkedin_action = linkedin_decision.take().map(|decision| {
            engine_receipt_fields.extend(decision.receipt_fields);
            engine_policy_trace.extend(decision.policy_trace);
            decision.action
        });

        let (
            gate_decision_ref,
            gate_outcome_kind,
            gate_outcome,
            gate_reason_codes,
            gate_receipt_reasons,
            effector_charge,
            effect_state,
            outcome,
            execution,
        ) = if admit_for_execution {
            let prepared = crate::outbound_chokepoint::PreparedEffect {
                attempt_id,
                call_seq: 0,
                server: request.intent.channel.clone(),
                tool: verb_contract.kind.clone(),
                payload: payload.ok_or(Error::InvariantViolation(
                    "admitted dispatch has no frozen payload",
                ))?,
                idempotency_supported,
                resolved_endpoint: None,
                gate: effect,
                budget_class: crate::outbound_intent_ledger::BudgetClass::Send,
                authorization: crate::outbound_chokepoint::PreparedAuthorization::None,
                verified_actor,
            };
            let authority = crate::outbound_consent::OutboundBindingAuthority::for_vault(vault)?;
            let mut transport =
                DispatchChokepointTransport::new(vault, &request, verb_contract, sink);
            let effect_result = crate::outbound_chokepoint::execute_outbound_effect(
                vault,
                &authority,
                crate::outbound_chokepoint::OutboundEffectCommand::New(prepared),
                request.occurred_at,
                &mut transport,
            )
            .map_err(|error| match error {
                crate::outbound_intent_ledger::IntentLedgerError::InvalidBoundActor => {
                    OutboundDispatchError::InvalidBoundActor
                }
                error => OutboundDispatchError::Chokepoint(error),
            })?;
            let gate_outcome = effect_result
                .gate_outcome
                .clone()
                .unwrap_or_else(|| "allow".to_owned());
            let gate_outcome_kind = match gate_outcome.as_str() {
                "allow" => GateOutcome::Allow,
                "pending" => GateOutcome::Pending,
                "deny" => GateOutcome::Deny,
                _ => {
                    return Err(OutboundDispatchError::Engine(Error::InvariantViolation(
                        "invalid chokepoint gate outcome",
                    )));
                }
            };
            let outcome = match effect_result.dispatch.state {
                Some(crate::outbound_intent_ledger::IntentState::Done) => {
                    OutboundDispatchOutcome::DeliveredToChannel
                }
                Some(crate::outbound_intent_ledger::IntentState::Pending) => {
                    if transport.execution.as_ref().is_some_and(|execution| {
                        execution.kind == OutboundExecutionOutcomeKind::Failed
                    }) {
                        OutboundDispatchOutcome::Failed
                    } else {
                        OutboundDispatchOutcome::Held
                    }
                }
                Some(crate::outbound_intent_ledger::IntentState::Abandoned) => {
                    OutboundDispatchOutcome::Failed
                }
                None if gate_outcome_kind == GateOutcome::Pending => OutboundDispatchOutcome::Held,
                None => OutboundDispatchOutcome::Suppressed,
            };
            (
                // On a ledger replay the chokepoint returns no gate decision id
                // (the gate ran, and was recorded, on the original send). Omit
                // the ref rather than fabricate a non-queryable `intent:` value
                // that would break the receipt's `gate:` audit link.
                effect_result.gate_decision_id,
                gate_outcome_kind,
                gate_outcome,
                effect_result.gate_reason_codes,
                effect_result.gate_receipt_reasons,
                effect_result.budget_charge,
                effect_result.dispatch.state,
                outcome,
                transport.execution,
            )
        } else {
            let mut wtxn = vault.store.env.write_txn().map_err(Error::from)?;
            if let Some((actor, actor_class)) = verified_actor {
                let entity_type = vault
                    .get_entity_type_in_txn(&wtxn, &actor)?
                    .ok_or(OutboundDispatchError::InvalidBoundActor)?;
                crate::provenance::validate_actor_class(entity_type, actor_class)?;
            }
            let policy = gate::resolve_policy_manifest(&vault.store, &wtxn)?;
            let (gate_decision_id, gate_decision, _) = gate::check_external_effect_policy(
                &vault.store,
                &mut wtxn,
                &effect,
                &policy,
                false,
            )?;
            wtxn.commit().map_err(Error::from)?;
            let gate_outcome_kind = gate_decision.outcome();
            let outcome = match gate_outcome_kind {
                GateOutcome::Pending => OutboundDispatchOutcome::Held,
                GateOutcome::Deny => OutboundDispatchOutcome::Suppressed,
                GateOutcome::Allow => match &window_decision {
                    OutboundDeliveryWindowDecision::Hold { .. } => OutboundDispatchOutcome::Held,
                    OutboundDeliveryWindowDecision::Degrade { .. } => {
                        OutboundDispatchOutcome::Degraded
                    }
                    OutboundDeliveryWindowDecision::LetGo { .. } => OutboundDispatchOutcome::LetGo,
                    OutboundDeliveryWindowDecision::DeliverNow
                    | OutboundDeliveryWindowDecision::DeliverNowWithApnsCap { .. } => {
                        match linkedin_action {
                            Some(LinkedInSeatPolicyAction::Hold) => OutboundDispatchOutcome::Held,
                            Some(LinkedInSeatPolicyAction::Suppress) => {
                                OutboundDispatchOutcome::Suppressed
                            }
                            Some(LinkedInSeatPolicyAction::Allow) | None => {
                                return Err(OutboundDispatchError::Engine(
                                    Error::InvariantViolation(
                                        "admitted dispatch missed chokepoint",
                                    ),
                                ));
                            }
                        }
                    }
                },
            };
            (
                Some(format!("gate:{}", gate_decision_id.to_hex())),
                gate_outcome_kind,
                gate_outcome_kind.as_str().to_owned(),
                gate_decision
                    .reason_codes()
                    .iter()
                    .map(|reason| reason.as_str().to_owned())
                    .collect(),
                gate_decision
                    .receipt_reasons()
                    .iter()
                    .map(|reason| (*reason).to_owned())
                    .collect(),
                None,
                None,
                outcome,
                None,
            )
        };

        let mut receipt = outbound_intent_receipt(
            request.receipt_id.clone(),
            request.intent_ref.clone(),
            &request.intent,
            request.occurred_at,
            outcome.as_str(),
        );
        receipt
            .policy_trace
            .extend(gate_reason_codes.iter().cloned());
        receipt
            .policy_trace
            .extend(gate_receipt_reasons.iter().cloned());
        receipt.policy_trace.push(window_decision.policy_trace());
        receipt.policy_trace.extend(engine_policy_trace);
        if let Some(gate_decision_ref) = gate_decision_ref.as_deref() {
            receipt
                .fields
                .insert("gate_decision_ref".to_owned(), gate_decision_ref.to_owned());
        }
        receipt
            .fields
            .insert("gate_outcome".to_owned(), gate_outcome.clone());
        receipt
            .fields
            .insert("gate_reason_codes".to_owned(), gate_reason_codes.join(","));
        if !gate_receipt_reasons.is_empty() {
            receipt.fields.insert(
                "gate_receipt_reasons".to_owned(),
                gate_receipt_reasons.join(","),
            );
        }
        // The provider's own stated cool-down, normalized to whole seconds and
        // stamped beside the gate evidence rather than mixed into it. Only a
        // well-formed value is promoted: the connector's raw string still
        // reaches the receipt verbatim through
        // `append_execution_receipt_fields`, so this adds a machine-readable
        // re-arm authority without editing what the provider actually said.
        if let Some(retry_after) = execution.as_ref().and_then(provider_retry_after_secs) {
            receipt.fields.insert(
                PROVIDER_RETRY_AFTER_FIELD.to_owned(),
                retry_after.to_string(),
            );
        }
        if let Some(effect_state) = effect_state {
            receipt
                .fields
                .insert("intent_state".to_owned(), effect_state.as_str().to_owned());
        }
        // GOV-02 (ONE-1418) budget legibility: stamped only when a governing
        // connector key's budget stage ran. `budget_debit`/`budget` are the
        // exact fields the RS4 receipt projections already sum. A refused
        // send stamps `budget_debit: "0"` next to the deny reason — the
        // honest record. `budget` = min remaining over the rows MATCHED by
        // this dispatch (the binding constraint — M4 resolution 2026-07-10).
        if let Some(charge) = effector_charge.as_ref() {
            receipt.fields.insert(
                "connector_key_ref".to_owned(),
                format!("ckey:{}", charge.key_ref.to_hex()),
            );
            receipt
                .fields
                .insert("budget_debit".to_owned(), charge.sends_debit.to_string());
            let binding_remaining = charge
                .read
                .rows
                .iter()
                .filter(|row| charge.matched_rows.contains(&row.row_index))
                .map(|row| row.remaining)
                .min();
            if let Some(binding_remaining) = binding_remaining {
                receipt
                    .fields
                    .insert("budget".to_owned(), binding_remaining.to_string());
            }
        }
        receipt.fields.insert(
            "channel_call".to_owned(),
            verb_contract.channel_call.clone(),
        );
        receipt.fields.insert(
            "interruption_class".to_owned(),
            serde_json::to_value(&verb_contract.interruption_class)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_else(|| "unknown".to_owned()),
        );
        receipt.fields.insert(
            "retry_class".to_owned(),
            serde_json::to_value(&verb_contract.retry_class)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_else(|| "unknown".to_owned()),
        );
        receipt.fields.insert(
            "policy_risk".to_owned(),
            match policy_risk {
                ExternalEffectPolicyRisk::Normal => "normal",
                ExternalEffectPolicyRisk::HoldToProposal => "hold_to_proposal",
            }
            .to_owned(),
        );
        for (key, value) in engine_receipt_fields {
            receipt.fields.insert(key, value);
        }
        append_optional_receipt_field(
            &mut receipt,
            "content_ref",
            request.intent.content_ref.as_deref(),
        );
        append_optional_receipt_field(
            &mut receipt,
            "idempotency_key",
            request.intent.idempotency_key.as_deref(),
        );
        append_optional_receipt_field(
            &mut receipt,
            "dedupe_key",
            request.intent.dedupe_key.as_deref(),
        );
        append_optional_receipt_field(
            &mut receipt,
            "channel_identity_ref",
            request
                .channel_identity_ref
                .map(|identity_ref| identity_ref.to_hex())
                .as_deref(),
        );
        append_optional_receipt_field(
            &mut receipt,
            "counterparty_ref",
            request.counterparty_ref.as_deref(),
        );
        if let Some(execution) = execution {
            receipt.fields.insert(
                "delivery_may_have_occurred".to_owned(),
                execution.delivery_may_have_occurred.to_string(),
            );
            append_optional_receipt_field(
                &mut receipt,
                "provider_ref",
                execution.provider_ref.as_deref(),
            );
            append_optional_receipt_field(
                &mut receipt,
                "retry_state",
                execution.retry_state.as_deref(),
            );
            append_execution_receipt_fields(&mut receipt, &execution.receipt_fields);
        }
        append_dispatch_outcome_receipt_fields(
            &mut receipt,
            outcome,
            gate_outcome_kind,
            &gate_reason_codes,
            &gate_receipt_reasons,
        );
        append_window_receipt_fields(&mut receipt, &window_decision);
        append_window_resolution_receipt_fields(&mut receipt, &window_resolution, &window_decision);
        if let Some(context) = request.context_receipt.as_ref() {
            context.append_to_fields(&mut receipt.fields);
        }

        let (effector_budget, budget_ladder_events) = match effector_charge {
            Some(charge) => (Some(charge.read), charge.ladder_events),
            None => (None, Vec::new()),
        };
        Ok(OutboundDispatchResult {
            outcome,
            gate_decision_id: gate_decision_ref,
            gate_outcome,
            gate_reason_codes,
            receipt,
            effector_budget,
            budget_ladder_events,
        })
    }
}
