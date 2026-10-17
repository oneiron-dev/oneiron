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
    OutboundRetryClass, OutboundVerbContract, normalize_key, outbound_verb_contract,
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
    /// The owner whose approval the effect carries; admission rechecks it.
    pub(super) owner_proof: Option<crate::consent::AuthenticatedOwner>,
    pub(super) step_binding: Option<crate::llm::StepEffectBinding>,
    pub(super) payload: Option<Vec<u8>>,
    pub(super) native_mail_recipient: bool,
}
impl PreparedOutboundDispatch {
    pub(super) fn prepare(
        vault: &Vault,
        mut request: OutboundDispatchRequest,
        verified_actor: Option<(EntityId, EdgeActorClass)>,
        step_binding: Option<crate::llm::StepEffectBinding>,
    ) -> Result<Self, OutboundDispatchError> {
        crate::dreamer_runner::maintenance::representation::validate_dispatch(vault, &request)?;
        if !crate::task_verb::validate_ask_soft_confirm_dispatch(vault, &request)? {
            return Err(OutboundDispatchError::ObsoleteAskConfirmation);
        }
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
        // OF-123 act-now guard: a target the agent took from a saved mention
        // waits until that mention is settled. A replayed task reads the
        // mention's state again here.
        if let Some(mention) = request.intent.mention.as_ref() {
            let unsettled = {
                let txn = vault.store.env.read_txn().map_err(Error::from)?;
                crate::dreamer_runner::maintenance::identity::mention_unsettled_in_txn(
                    vault, &txn, mention,
                )?
            };
            if let Some(name) = unsettled {
                return Err(OutboundDispatchError::Engine(Error::Record(
                    crate::error::RecordError::IdentityUnsettled { name },
                )));
            }
        }

        let verb_contract = outbound_verb_contract(&request.intent.channel, &request.intent.verb)?;
        vault.require_builtin_channel_pack(&request.intent.channel)?;
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
        (request.channel_identity_ref, request.facet_ref) = resolve_dispatch_sender(
            vault,
            &request,
            replay
                .as_ref()
                .map(crate::outbound_intent_ledger::IntentLedgerRecord::payload),
        )?;
        let native_mail_recipient =
            bind_native_mail_recipient(vault, &mut request, verb_contract, replay.as_ref())?;
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
            || request.gate.policy_risk
                == crate::outbound::OutboundDispatchPolicyRisk::HoldToProposal
        {
            ExternalEffectPolicyRisk::HoldToProposal
        } else if native_mail_recipient {
            // The trusted native-mail manifest row decides known vs cold in
            // the Gate transaction. The generic email capability's advisory
            // risk flag must not pre-hold every known-recipient send; caller
            // and space-specific explicit holds remain restrictive above.
            ExternalEffectPolicyRisk::Normal
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
            owner_proof: None,
            step_binding,
            payload: None,
            native_mail_recipient,
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
            dreamer_step: self
                .step_binding
                .map(crate::llm::StepEffectBinding::frozen_value),
            calendar_invite: request.calendar_invite.as_ref(),
            space_posting: self.space_posting.as_ref(),
            actor_class: &request.actor.actor_class,
            actor_ref: request.actor.actor_ref.as_deref(),
            actor_entity_ref: request.actor.actor_entity_ref.map(|id| id.to_hex()),
            channel_identity_ref: request.channel_identity_ref.map(|id| id.to_hex()),
            counterparty_ref: request.counterparty_ref.as_deref(),
            native_mail_recipient: self.native_mail_recipient.then_some(true),
            native_mail_logical_ref: self
                .native_mail_recipient
                .then_some(request.intent_ref.as_str()),
            has_opted_in: request.gate.has_opted_in,
            has_permission: request.gate.has_permission,
            requested_policy_risk: request.gate.policy_risk.to_gate().as_str(),
            policy_risk: self.policy_risk.as_str(),
            originating_session_ref: request.originating_session_ref.as_deref(),
            reply_thread_ref: request.reply_thread_ref.as_deref(),
            facet_ref: request.facet_ref.map(|id| id.to_hex()),
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
/// Only an executable Pending retry needs the native sender live today.
/// Parked Pending and terminal records remain readable without transport.
/// A member mailbox (OF-374) shares the canonical mail binding, so its live
/// send-capable row answers here too.
pub(super) fn require_native_mail_retry_sender(
    vault: &Vault,
    request: &OutboundDispatchRequest,
    native_mail: bool,
) -> std::result::Result<(), OutboundDispatchError> {
    if native_mail {
        let sender = request
            .channel_identity_ref
            .ok_or(Error::InvalidConfig("missing native-mail sender".into()))?;
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        if !crate::channel_identity_provider::native_mail::is_native_mail_sender_in_txn(
            &vault.store,
            &txn,
            sender,
        )? && !crate::channel_identity_provider::member_mail::is_member_mail_sender_in_txn(
            &vault.store,
            &txn,
            sender,
        )? {
            return Err(Error::InvalidConfig("inactive native-mail sender".into()).into());
        }
    }
    Ok(())
}

/// Bind one canonical native-mail recipient to gate, ledger and transport.
/// The generic dispatch API must not bypass the adapter's target check.
/// OF-374: a delegated member mailbox is bound the same way, so its per-send
/// approval digest and replay proof are the canonical mail operation's.
fn bind_native_mail_recipient(
    vault: &Vault,
    request: &mut OutboundDispatchRequest,
    contract: &crate::outbound::capability::OutboundVerbContract,
    replay: Option<&crate::outbound_intent_ledger::IntentLedgerRecord>,
) -> std::result::Result<bool, OutboundDispatchError> {
    // The accepted contract, not the caller's raw spelling, is the operation
    // the Gate and the sink execute. The raw spelling stays frozen unchanged.
    if normalize_key(&request.intent.channel) != "email" || contract.kind != "send" {
        return Ok(false);
    }
    let Some(identity) = request.channel_identity_ref else {
        return Ok(false);
    };
    let native = if let Some(record) = replay {
        let frozen: serde_json::Value =
            serde_json::from_slice(record.payload()).map_err(|_| invalid_replay())?;
        match frozen.get("native_mail_recipient") {
            Some(serde_json::Value::Bool(true)) => true,
            None => false,
            _ => return Err(invalid_replay()),
        }
    } else {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        let structural =
            crate::channel_identity_provider::native_mail::is_native_mail_identity_in_txn(
                &vault.store,
                &txn,
                identity,
            )?;
        if structural
            && !crate::channel_identity_provider::native_mail::is_native_mail_sender_in_txn(
                &vault.store,
                &txn,
                identity,
            )?
        {
            return Err(Error::InvalidConfig("inactive native-mail sender".into()).into());
        }
        let member = crate::channel_identity_provider::member_mail::is_member_mail_identity_in_txn(
            &vault.store,
            &txn,
            identity,
        )?;
        if member
            && !crate::channel_identity_provider::member_mail::is_member_mail_sender_in_txn(
                &vault.store,
                &txn,
                identity,
            )?
        {
            return Err(Error::InvalidConfig("inactive member-mail sender".into()).into());
        }
        structural || member
    };
    if !native {
        return Ok(false);
    }
    let canonical =
        crate::channel_identity_provider::native_mail::CanonicalMailSend::from_request(request)?;
    request.intent.channel = "email".to_owned();
    request.intent.target = canonical.recipient.clone();
    request.counterparty_ref = Some(canonical.recipient);
    Ok(true)
}

pub(super) fn invalid_replay() -> OutboundDispatchError {
    OutboundDispatchError::Chokepoint(IntentLedgerError::InvalidRecord(
        "outbound dispatch replay does not match its admitted binding",
    ))
}

/// The sender identity and facet a send goes out as. A replay reads both
/// from its frozen binding; a new send on a reply thread wears the thread's
/// pin (OF-272); any other new send enriches by connector and actor.
fn resolve_dispatch_sender(
    vault: &Vault,
    request: &OutboundDispatchRequest,
    replay_payload: Option<&[u8]>,
) -> std::result::Result<(Option<EntityId>, Option<EntityId>), OutboundDispatchError> {
    if let Some(payload) = replay_payload {
        let frozen: serde_json::Value =
            serde_json::from_slice(payload).map_err(|_| invalid_replay())?;
        let sender = frozen_entity(frozen.get("channel_identity_ref"), true)?;
        let facet = frozen_entity(frozen.get("facet_ref"), false)?;
        if (request.channel_identity_ref.is_some() && request.channel_identity_ref != sender)
            || (request.facet_ref.is_some() && request.facet_ref != facet)
        {
            return Err(invalid_replay());
        }
        return Ok((sender, facet));
    }
    let (requested, facet) = match request.reply_thread_ref.as_deref() {
        Some(thread_ref) => match reply_thread_pin(vault, request, thread_ref)? {
            Some(pin) => (Some(pin.identity_ref), pin.facet_ref),
            None => (request.channel_identity_ref, request.facet_ref),
        },
        None => (request.channel_identity_ref, request.facet_ref),
    };
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    let sender = enrich_dispatch_channel_identity(
        &vault.store,
        &txn,
        &request.intent.channel,
        request.actor.actor_entity_ref.as_ref(),
        requested,
    )?;
    Ok((sender, facet))
}

/// One frozen entity ref: a hex string, or null where `nullable` (the
/// sender is frozen even when absent; an absent facet is elided).
fn frozen_entity(
    value: Option<&serde_json::Value>,
    nullable: bool,
) -> std::result::Result<Option<EntityId>, OutboundDispatchError> {
    match value {
        Some(serde_json::Value::String(value)) => Ok(Some(
            EntityId::from_hex(value).map_err(|_| invalid_replay())?,
        )),
        Some(serde_json::Value::Null) if nullable => Ok(None),
        None if !nullable => Ok(None),
        _ => Err(invalid_replay()),
    }
}

/// OF-272 reply selection: the thread's first passport pins who speaks on
/// it. A reply from another actor, or one that names another identity or
/// facet, is refused; the composer decides what to say about the pin.
fn reply_thread_pin(
    vault: &Vault,
    request: &OutboundDispatchRequest,
    thread_ref: &str,
) -> std::result::Result<Option<crate::thread_passport::ThreadMask>, OutboundDispatchError> {
    let pin = match vault.sticky_thread_mask(thread_ref, None)? {
        crate::thread_passport::StickyMaskDecision::Keep(pin)
        | crate::thread_passport::StickyMaskDecision::Conflict { pinned: pin, .. } => pin,
        crate::thread_passport::StickyMaskDecision::Unset => return Ok(None),
    };
    if request.actor.actor_entity_ref != Some(pin.actor_ref)
        || request
            .channel_identity_ref
            .is_some_and(|identity| identity != pin.identity_ref)
        || request
            .facet_ref
            .is_some_and(|facet| Some(facet) != pin.facet_ref)
    {
        return Err(Error::InvalidConfig(
            "the reply thread is pinned to another identity, facet or actor".to_owned(),
        )
        .into());
    }
    Ok(Some(pin))
}
