//! One normalized outbound request and the single ledger replay validator.
use super::{
    enrich_dispatch_channel_identity, frozen_payload::FrozenOutboundPayload,
    policy_risk::outbound_dispatch_policy_risk,
};
use crate::attempt_queue::AttemptId;
use crate::campaign::send_hygiene::inject_campaign_email_hygiene_headers;
use crate::counterparty_contact::normalize_channel_class;
use crate::edge::EdgeActorClass;
use crate::error::{Error, OffRecordError};
use crate::gate::ExternalEffectPolicyRisk;
use crate::linkedin_connector::{LINKEDIN_CHANNEL, LINKEDIN_CONNECT_REQUEST_VERB};
use crate::outbound::capability::{
    OutboundRetryClass, OutboundVerbContract, outbound_verb_contract,
};
use crate::outbound::dispatch_attempt_id::outbound_dispatch_attempt_id;
use crate::outbound::dispatch_types::{OutboundDispatchError, OutboundDispatchRequest};
use crate::outbound_intent_ledger::{
    IntentLedgerError, IntentLedgerRecord, IntentState, read_intent_for_attempt_in_txn,
};
use crate::ports::TombstoneStore;
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Exact effect binding. The full frozen bytes, not a connector-local field list,
/// are the only replay identity. Receipt id/time are separate per-try evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct FrozenDispatchIdentity {
    pub(crate) attempt_ref: String,
    pub(crate) payload: Vec<u8>,
}

pub(super) struct PreparedOutboundDispatch {
    pub(super) request: OutboundDispatchRequest,
    pub(super) verb_contract: &'static OutboundVerbContract,
    pub(super) idempotency_supported: bool,
    pub(super) attempt_id: AttemptId,
    pub(super) replay: Option<IntentLedgerRecord>,
    pub(super) space_posting: Option<crate::channel_identity_autonomy::FrozenSpacePosting>,
    pub(super) policy_risk: ExternalEffectPolicyRisk,
    pub(super) verified_actor: Option<(EntityId, EdgeActorClass)>,
    pub(super) payload: Option<Vec<u8>>,
}
impl PreparedOutboundDispatch {
    pub(super) fn prepare(
        vault: &Vault,
        mut request: OutboundDispatchRequest,
        verified_actor: Option<(EntityId, EdgeActorClass)>,
    ) -> Result<Self, OutboundDispatchError> {
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
        // A queue-only dedupe key cannot make an ambiguous remote send safe
        // to replay; native keys and semantic replacement can.
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
        Ok(Self {
            request,
            verb_contract,
            idempotency_supported,
            attempt_id,
            replay,
            space_posting,
            policy_risk,
            verified_actor,
            payload: None,
        })
    }
    /// The same freeze and replay proof runs for every normal call and every
    /// completed-result lookup. It never emits a gate decision or calls a sink.
    pub(super) fn freeze_and_validate(
        &mut self,
        vault: &Vault,
    ) -> Result<(), OutboundDispatchError> {
        if self.payload.is_some() {
            return Ok(());
        }
        let request = &self.request;
        let mut hygiene_headers = BTreeMap::new();
        inject_campaign_email_hygiene_headers(
            &normalize_channel_class(&request.intent.channel),
            &mut hygiene_headers,
            request.campaign_unsubscribe.as_ref(),
        )?;
        let payload = serde_json::to_vec(&FrozenOutboundPayload {
            intent: &request.intent,
            hygiene_headers,
            calendar_invite: request.calendar_invite.as_ref(),
            space_posting: self.space_posting.as_ref(),
            actor_class: &request.actor.actor_class,
            actor_ref: request.actor.actor_ref.as_deref(),
            actor_entity_ref: request.actor.actor_entity_ref.map(|id| id.to_hex()),
            channel_identity_ref: request.channel_identity_ref.map(|id| id.to_hex()),
            counterparty_ref: request.counterparty_ref.as_deref(),
            has_opted_in: request.gate.has_opted_in,
            has_permission: request.gate.has_permission,
            requested_policy_risk: request.gate.policy_risk.to_gate().as_str(),
            policy_risk: self.policy_risk.as_str(),
            originating_session_ref: request.originating_session_ref.as_deref(),
        })
        .map_err(|_| Error::InvariantViolation("outbound intent freeze failed"))?;
        if let Some(record) = self.replay.as_ref() {
            if record.server != request.intent.channel
                || record.tool != self.verb_contract.kind
                || record.payload() != payload.as_slice()
                || record.idempotency_supported != self.idempotency_supported
                || !record.budget_accounting.budget_class.is_send()
                || record.resolved_endpoint.is_some()
                || record.authorization_binding.is_some()
                || record.capability_provenance().is_some()
            {
                return Err(invalid_replay());
            }
            if let Some((actor, actor_class)) = self.verified_actor {
                let txn = vault.store.env.read_txn().map_err(Error::from)?;
                if vault.port_tombstone_is_deleted(&txn, &actor)? {
                    return Err(OutboundDispatchError::InvalidBoundActor);
                }
                let entity_type = vault
                    .get_entity_type_in_txn(&txn, &actor)?
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
        self.payload = Some(payload);
        Ok(())
    }
    pub(super) fn replay_done(&self) -> bool {
        self.replay
            .as_ref()
            .is_some_and(|r| r.state == IntentState::Done)
    }
    pub(super) fn identity(&self) -> Option<FrozenDispatchIdentity> {
        self.payload.as_ref().map(|payload| FrozenDispatchIdentity {
            attempt_ref: crate::entity_id::bytes_to_hex_lower(self.attempt_id.as_bytes()),
            payload: payload.clone(),
        })
    }
}
pub(super) fn invalid_replay() -> OutboundDispatchError {
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
