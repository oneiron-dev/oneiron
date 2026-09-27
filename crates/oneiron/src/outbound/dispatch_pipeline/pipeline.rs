//! O2 resolve-gate-window-execute dispatch pipeline: dispatch, verified-actor dispatch, and the dispatch_inner spine.
use super::enrich_dispatch_channel_identity;
use super::frozen_payload::FrozenOutboundPayload;
use super::policy_risk::outbound_dispatch_policy_risk;
use crate::Vault;
use crate::campaign::send_hygiene::inject_campaign_email_hygiene_headers;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, OffRecordError};
use crate::gate::ExternalEffectPolicyRisk;
use crate::linkedin_connector::{LINKEDIN_CHANNEL, LINKEDIN_CONNECT_REQUEST_VERB};
use crate::outbound::capability::{OutboundRetryClass, normalize_key, outbound_verb_contract};
use crate::outbound::dispatch_attempt_id::outbound_dispatch_attempt_id;
use crate::outbound::dispatch_types::{
    OutboundDispatchError, OutboundDispatchRequest, OutboundDispatchResult, OutboundExecutionSink,
};
use crate::outbound_intent_ledger::{IntentLedgerError, read_intent_for_attempt_in_txn};
use std::collections::BTreeMap;
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
        crate::dreamer_runner::maintenance::representation::validate_dispatch(vault, &request)?;
        // OF-326 talk-only (ONE-1546): an intent originating from a session
        // currently in off-record mode is rejected before verb resolution —
        // the typed error carries the exit-prompt semantics. Intents from a
        // session flipped back on-record dispatch normally, and the OF-333
        // floor below still classifies every real egress.
        if let Some(session_ref) = request.originating_session_ref.as_deref()
            && let Some(session) = vault.off_record_session(session_ref)?
            && session.mode != crate::off_record::OffRecordMode::OnRecord
        {
            return Err(OutboundDispatchError::Engine(Error::OffRecord(
                OffRecordError::OffRecordTalkOnly {
                    session_ref: session_ref.to_owned(),
                },
            )));
        }

        let verb_contract = outbound_verb_contract(&request.intent.channel, &request.intent.verb)?;
        // Scheduled tasks cannot supply a seat snapshot today. Never let that
        // optional request field turn a LinkedIn connect into an ungated send.
        if request.intent.channel == LINKEDIN_CHANNEL
            && verb_contract.kind == LINKEDIN_CONNECT_REQUEST_VERB
            && request.linkedin_sandbox_policy.is_none()
        {
            return Err(OutboundDispatchError::Engine(Error::InvalidConfig(
                "LinkedIn connect request requires current seat policy".to_owned(),
            )));
        }
        // Queue dedupe cannot prove an uncertain remote send did not happen.
        // Only provider-native keys and in-place replacements are replay-safe.
        let idempotency_supported = matches!(
            verb_contract.retry_class,
            OutboundRetryClass::IdempotentNative | OutboundRetryClass::ReplaceIdempotent
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
        request.channel_identity_ref = resolve_dispatch_sender(
            vault,
            &request,
            replay
                .as_ref()
                .map(crate::outbound_intent_ledger::IntentLedgerRecord::payload),
        )?;
        let space_posting = {
            let txn = vault.store.env.read_txn().map_err(Error::from)?;
            vault.outbound_space_posting_in_txn(
                &txn,
                request.channel_identity_ref,
                &request.intent.target,
            )?
        };
        let policy_risk = if space_posting
            .as_ref()
            .is_some_and(crate::channel_identity_autonomy::FrozenSpacePosting::policy_risk)
        {
            ExternalEffectPolicyRisk::HoldToProposal
        } else {
            outbound_dispatch_policy_risk(request.gate, verb_contract)
        };
        let window_resolution =
            crate::outbound::window_door::outbound_delivery_window_resolution_at_door(
                vault,
                &request,
                verb_contract,
            )?;
        let window_decision =
            crate::outbound::window_door::outbound_delivery_window_decision_at_door(
                &request,
                &window_resolution,
            );
        crate::outbound::window_door::apply_apns_window_cap(&mut request, &window_decision);
        let admission = super::admission::AdmissionStage::evaluate(
            &request,
            verb_contract,
            window_resolution,
            window_decision,
        );
        let effect = super::govern::gate_input(&request, verb_contract, policy_risk);
        // Only executable sends (or replays needing binding validation) freeze bytes.
        let payload = if matches!(
            admission.decision,
            super::admission::DispatchAdmission::Execute
        ) || replay.is_some()
        {
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
                space_posting: space_posting.as_ref(),
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

        let verdict = match admission.decision {
            super::admission::DispatchAdmission::Execute => {
                super::effect::execute_admitted(super::effect::EffectInput {
                    vault,
                    request: &request,
                    sink,
                    verb_contract,
                    effect,
                    payload: payload.ok_or(Error::InvariantViolation(
                        "admitted dispatch has no frozen payload",
                    ))?,
                    attempt_id,
                    idempotency_supported,
                    verified_actor,
                })?
            }
            super::admission::DispatchAdmission::Park { outcome } => super::govern::govern_parked(
                vault,
                &request,
                &effect,
                verified_actor,
                space_posting.as_ref(),
                outcome,
            )?,
        };
        Ok(crate::outbound::receipt_fields::dispatch_result_receipt(
            &request,
            verb_contract,
            policy_risk,
            space_posting.as_ref(),
            &admission,
            verdict,
        ))
    }
}

fn invalid_replay() -> OutboundDispatchError {
    OutboundDispatchError::Chokepoint(IntentLedgerError::InvalidRecord(
        "outbound dispatch replay does not match its admitted binding",
    ))
}

fn resolve_dispatch_sender(
    vault: &Vault,
    request: &OutboundDispatchRequest,
    replay_payload: Option<&[u8]>,
) -> std::result::Result<Option<EntityId>, OutboundDispatchError> {
    if let Some(payload) = replay_payload {
        let frozen: serde_json::Value =
            serde_json::from_slice(payload).map_err(|_| invalid_replay())?;
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
        Ok(sender)
    } else {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        enrich_dispatch_channel_identity(
            &vault.store,
            &txn,
            &request.intent.channel,
            request.actor.actor_entity_ref.as_ref(),
            request.channel_identity_ref,
        )
        .map_err(Into::into)
    }
}
