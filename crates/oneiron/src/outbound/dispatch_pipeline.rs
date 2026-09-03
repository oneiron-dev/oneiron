use std::collections::BTreeMap;

use serde::Serialize;

use super::OutboundDeliveryWindowDecision;
use super::capability::{
    OutboundRetryClass, OutboundVerbContract, normalize_key, outbound_verb_contract,
};
use super::dispatch_types::{
    OutboundDispatchError, OutboundDispatchGate, OutboundDispatchOutcome,
    OutboundDispatchPolicyRisk, OutboundDispatchRequest, OutboundDispatchResult,
    OutboundExecutionOutcome, OutboundExecutionOutcomeKind, OutboundExecutionRequest,
    OutboundExecutionSink,
};
use super::intent::OutboundIntent;
use super::receipt_fields::{
    append_dispatch_outcome_receipt_fields, append_execution_receipt_fields,
    append_optional_receipt_field, append_window_receipt_fields,
    append_window_resolution_receipt_fields,
};
use super::window_door::{
    outbound_delivery_window_decision_at_door, outbound_delivery_window_resolution_at_door,
};
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::calendar::invite::CalendarInvitePayload;
use crate::campaign::send_hygiene::inject_campaign_email_hygiene_headers;
use crate::channel_identity::{
    ChannelIdentityBinding, ChannelIdentityState, decode_channel_identity_body,
};
use crate::counterparty_contact::normalize_channel_class;
use crate::delivery_window::DeliveryWindowApnsInterruptionLevel;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::gate::{self, ExternalEffectGateInput, ExternalEffectPolicyRisk, GateOutcome};
use crate::linkedin_connector::LinkedInSeatPolicyAction;
use crate::receipt::outbound_intent_receipt;
use crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY;
use crate::store::Store;
use crate::vault::entity_id_from_type_index_key;

/// The bytes one outbound effect freezes: the intent, plus the CA-05 send
/// hygiene headers derived from that same frozen metadata.
///
/// Flattened and elided-when-empty, the way every optional field on
/// [`OutboundIntent`] is: the frozen bytes are what a connector reads and what
/// the ledger hashes into an intent id, so a send that carries no hygiene
/// headers says nothing about them rather than freezing an empty map. Ordering
/// is fixed by the struct's field order and by the [`BTreeMap`], because these
/// bytes are the retry contract.
#[derive(Serialize)]
struct FrozenOutboundPayload<'a> {
    #[serde(flatten)]
    intent: &'a OutboundIntent,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    hygiene_headers: BTreeMap<String, String>,
    /// CAL-04's exact five-field iMIP body, elided for every send that is not
    /// a calendar invite. It carries `ics_blob_ref` and never the `.ics` bytes,
    /// so the frozen payload stays small and the document a retry re-sends is
    /// byte-identical by reference rather than by re-rendering.
    #[serde(skip_serializing_if = "Option::is_none")]
    calendar_invite: Option<&'a CalendarInvitePayload>,
}

/// Stateless O2 resolve -> gate -> window -> execute -> receipt pipeline.
#[derive(Clone, Copy, Debug, Default)]
pub struct OutboundDispatchPipeline;

/// Resolves the OF-347 channel identity a connector key sends through.
///
/// ONE-1868 leg 2, pure ENRICHMENT: the opt-out verdict rests on
/// `(counterparty, channel_class)`, never on this value. Nothing new is minted —
/// the governing connector key (OF-277) names the sending actor, and the
/// ChannelIdentity bound to that actor on the connector's channel is the
/// identity that will carry the send. Missing, unregistered, inactive, or
/// AMBIGUOUS all resolve to `None`: an arbitrary pick would put a
/// nondeterministic identity on the receipt, which is worse than none.
pub(crate) fn resolve_channel_identity_ref_for_connector(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    connector_key: &str,
    actor_entity_ref: Option<&EntityId>,
) -> crate::Result<Option<EntityId>> {
    let connector = normalize_key(connector_key);
    let Some((_, key_record)) =
        crate::connector_key::governing_connector_key(store, txn, &connector, actor_entity_ref)?
    else {
        return Ok(None);
    };
    let Some(bound_actor) = key_record
        .actor_entity_ref
        .or_else(|| actor_entity_ref.copied())
    else {
        return Ok(None);
    };

    let channel_class = normalize_channel_class(connector_key);
    let mut resolved = None;
    for entry in store
        .type_index
        .prefix_iter(txn, &[ENTITY_TYPE_CHANNEL_IDENTITY])?
    {
        let (key, _) = entry?;
        let id = entity_id_from_type_index_key(&key)?;
        let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
            return Err(Error::CorruptedIndex("channel identity entity row"));
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            return Err(Error::CorruptedIndex("channel identity entity header"));
        };
        if header.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
            return Err(Error::CorruptedIndex("channel identity entity type"));
        }
        let identity = decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        if identity.state != ChannelIdentityState::Active
            || normalize_channel_class(&identity.channel) != channel_class
            || identity.binding != ChannelIdentityBinding::agent(bound_actor)
        {
            continue;
        }
        if resolved.is_some() {
            return Ok(None);
        }
        resolved = Some(id);
    }
    Ok(resolved)
}

/// An explicit channel identity always wins; otherwise resolve it cheaply.
pub(crate) fn enrich_dispatch_channel_identity(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    connector_key: &str,
    actor_entity_ref: Option<&EntityId>,
    explicit: Option<EntityId>,
) -> crate::Result<Option<EntityId>> {
    match explicit {
        some @ Some(_) => Ok(some),
        None => {
            resolve_channel_identity_ref_for_connector(store, txn, connector_key, actor_entity_ref)
        }
    }
}

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
    pub(crate) fn dispatch_with_verified_actor<S: OutboundExecutionSink>(
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

        // ONE-1868 leg 2. Every shipping constructor (facade bridge, connector
        // task executor, direct dispatch) leaves `channel_identity_ref` unset,
        // so resolve it ONCE here — the pipeline all three funnel through —
        // rather than at each call site. Enrichment only: the opt-out verdict
        // below rests on `(counterparty, channel_class)` either way. The read
        // txn is scoped to this block so none is open when the stages below
        // take their write txns.
        request.channel_identity_ref = {
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
            // CA-05: the unsubscribe headers are derived ONCE, here, from the
            // metadata this send is about to freeze — before the gate runs and
            // long before any connector sees the call. A retry replays these
            // bytes instead of re-deriving, which is what makes the headers
            // byte-identical rather than merely equivalent.
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
            })
            .map_err(|_| {
                OutboundDispatchError::Engine(Error::InvariantViolation(
                    "outbound intent freeze failed",
                ))
            })?;
            // The ledger/charge identity follows the stable logical-send ref
            // when the caller supplies one, so fresh retries of the same logical
            // send collapse onto one paid intent while `intent_ref` stays the
            // sink-facing scheduled ref.
            let ledger_identity_ref = request
                .ledger_identity_ref
                .as_deref()
                .unwrap_or(&request.intent_ref);
            let attempt_id = outbound_dispatch_attempt_id(ledger_identity_ref)?;
            let prepared = crate::outbound_chokepoint::PreparedEffect {
                attempt_id,
                call_seq: 0,
                server: request.intent.channel.clone(),
                tool: verb_contract.kind.clone(),
                payload,
                idempotency_supported: !matches!(
                    verb_contract.retry_class,
                    OutboundRetryClass::NonIdempotentInterrupt
                ),
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

impl Vault {
    pub fn dispatch_outbound_intent<S: OutboundExecutionSink>(
        &self,
        request: OutboundDispatchRequest,
        sink: &mut S,
    ) -> std::result::Result<OutboundDispatchResult, OutboundDispatchError> {
        OutboundDispatchPipeline.dispatch(self, request, sink)
    }

    /// Facade-only dispatch seam: asserts the actor still resolves in the
    /// Gate transaction that persists this outbound decision.
    pub(crate) fn dispatch_outbound_intent_with_verified_actor<S: OutboundExecutionSink>(
        &self,
        request: OutboundDispatchRequest,
        sink: &mut S,
        actor: EntityId,
        actor_class: EdgeActorClass,
    ) -> std::result::Result<OutboundDispatchResult, OutboundDispatchError> {
        OutboundDispatchPipeline.dispatch_with_verified_actor(
            self,
            request,
            sink,
            actor,
            actor_class,
        )
    }
}

struct DispatchChokepointTransport<'a, S> {
    vault: &'a Vault,
    request: &'a OutboundDispatchRequest,
    verb_contract: &'static OutboundVerbContract,
    sink: &'a mut S,
    execution: Option<OutboundExecutionOutcome>,
}

impl<'a, S> DispatchChokepointTransport<'a, S> {
    fn new(
        vault: &'a Vault,
        request: &'a OutboundDispatchRequest,
        verb_contract: &'static OutboundVerbContract,
        sink: &'a mut S,
    ) -> Self {
        Self {
            vault,
            request,
            verb_contract,
            sink,
            execution: None,
        }
    }
}

impl<S: OutboundExecutionSink> crate::outbound_chokepoint::OutboundTransport
    for DispatchChokepointTransport<'_, S>
{
    fn send(
        &mut self,
        call: &crate::outbound_intent_ledger::FrozenOutboundCall,
    ) -> crate::outbound_intent_ledger::OutboundSendOutcome {
        if call.server() != self.request.intent.channel
            || call.tool() != self.verb_contract.kind
            || call.resolved_endpoint().is_some()
        {
            return invalid_frozen_call();
        }
        // The last in-process boundary before the connector: the hygiene
        // headers come out of the frozen bytes, never out of the live request.
        let Ok(hygiene_headers) = crate::outbound_chokepoint::frozen_call_hygiene_headers(call)
        else {
            return invalid_frozen_call();
        };
        // CAL-04, same discipline: a `calendar.invite` send resolves its
        // `text/calendar` part from the FROZEN blob ref here, at the last
        // in-process boundary, and never recomputes a UID, a SEQUENCE, or the
        // document itself. A verb-registered invite whose frozen bytes carry no
        // five-field body — or whose blob ref no longer dereferences — fails
        // closed rather than going out as a plain email about a meeting.
        let calendar_invite = if self.verb_contract.kind == crate::calendar::CALENDAR_INVITE_VERB {
            let Ok(payload) = crate::calendar::decode_frozen_calendar_invite(call.payload()) else {
                return invalid_frozen_call();
            };
            let Ok(part) = crate::calendar::build_calendar_invite_mime_part(self.vault, &payload)
            else {
                return invalid_frozen_call();
            };
            Some(part)
        } else {
            None
        };
        let execution_request = OutboundExecutionRequest {
            intent_ref: &self.request.intent_ref,
            intent: &self.request.intent,
            // The ledger id doubles as the frozen call's idempotency key, but a
            // sink must only be told it has provider idempotency when the verb
            // actually supports it. A non-idempotent send exposes no key, so the
            // transport cannot mistake the ledger id for a dedupe token.
            idempotency_key: if call.idempotency_supported() {
                call.idempotency_key()
            } else {
                None
            },
            verb_contract: self.verb_contract,
            channel_identity_ref: self.request.channel_identity_ref,
            counterparty_ref: self.request.counterparty_ref.as_deref(),
            hygiene_headers,
            apns_interruption_level: self.request.delivery_window_apns_interruption_level,
            calendar_invite,
        };
        let execution = self.sink.execute(&execution_request);
        let outcome = match execution.kind {
            OutboundExecutionOutcomeKind::DeliveredToChannel => {
                crate::outbound_intent_ledger::OutboundSendOutcome::Acked
            }
            OutboundExecutionOutcomeKind::Failed if execution.delivery_may_have_occurred => {
                crate::outbound_intent_ledger::OutboundSendOutcome::Ambiguous
            }
            OutboundExecutionOutcomeKind::Failed => {
                crate::outbound_intent_ledger::OutboundSendOutcome::Failed(
                    crate::outbound_intent_ledger::OutboundSendFailure {
                        kind:
                            crate::outbound_intent_ledger::OutboundFailureKind::TransportNotStarted,
                        code: None,
                    },
                )
            }
        };
        self.execution = Some(execution);
        outcome
    }
}

/// A frozen call the dispatch transport cannot honor verbatim.
fn invalid_frozen_call() -> crate::outbound_intent_ledger::OutboundSendOutcome {
    crate::outbound_intent_ledger::OutboundSendOutcome::Failed(
        crate::outbound_intent_ledger::OutboundSendFailure {
            kind: crate::outbound_intent_ledger::OutboundFailureKind::InvalidRequest,
            code: None,
        },
    )
}

fn outbound_dispatch_attempt_id(
    intent_ref: &str,
) -> std::result::Result<crate::attempt_queue::AttemptId, OutboundDispatchError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron.outbound.dispatch_attempt.v1");
    hasher.update(&(intent_ref.len() as u64).to_le_bytes());
    hasher.update(intent_ref.as_bytes());
    let bytes: [u8; 16] = hasher.finalize().as_bytes()[..16]
        .try_into()
        .expect("BLAKE3 prefix length is fixed");
    crate::attempt_queue::AttemptId::from_bytes(&bytes).map_err(OutboundDispatchError::Engine)
}

fn outbound_dispatch_policy_risk(
    gate: OutboundDispatchGate,
    verb_contract: &OutboundVerbContract,
) -> ExternalEffectPolicyRisk {
    if gate.policy_risk == OutboundDispatchPolicyRisk::HoldToProposal
        || verb_contract.capability_vs_permission.policy_risk
    {
        ExternalEffectPolicyRisk::HoldToProposal
    } else {
        gate.policy_risk.to_gate()
    }
}
