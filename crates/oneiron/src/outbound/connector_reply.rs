//! A standing connector's reply leg (OF-218). An agent's reply to a
//! surface-born connector event leaves through the ordinary outbound
//! pipeline, on the channel identity and thread the event arrived on. The
//! wake that carried the event is input data; it never sends.

use crate::Vault;
use crate::connector_key::events::ConnectorEvent;
use crate::delivery_window::DeliveryWindowResolvedLevel;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::surface_event::{SurfaceConnectorPayload, SurfaceCounterpartyStamp};

use super::OutboundDeliveryWindowDecision;
use super::dispatch_types::{
    OutboundDispatchActor, OutboundDispatchError, OutboundDispatchGate, OutboundDispatchRequest,
    OutboundDispatchResult, OutboundExecutionSink,
};
use super::intent::{OutboundIntent, OutboundIntentDraft, OutboundIntentTrigger};

/// One agent reply the host validated against the run that wrote it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorReply {
    /// The agent whose run wrote the reply.
    pub agent: EntityId,
    /// Stable per logical reply (the writing run's step, say); a retry of
    /// the same reply reuses it and replays instead of sending twice.
    pub reply_ref: String,
    /// Outbound verb, e.g. `send`.
    pub verb: String,
    /// The reply body's content ref.
    pub content_ref: String,
    pub occurred_at: u64,
}

/// A reply mapped onto its origin: the dispatch request, and the thread the
/// sink's per-send plan (keyed by `request.intent_ref`) posts into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorReplyDispatch {
    pub request: OutboundDispatchRequest,
    pub thread_ref: Option<String>,
}

/// Maps a host-validated agent reply onto an outbound dispatch on the
/// event's own channel, receiving identity, counterparty and thread.
///
/// # Errors
/// The event is not surface-born, or the reply comes from an agent other
/// than the one the event addressed.
pub fn connector_reply_request(
    event: &ConnectorEvent,
    reply: &ConnectorReply,
) -> Result<ConnectorReplyDispatch> {
    let origin = SurfaceConnectorPayload::from_connector_event(event)?;
    if origin.actor()? != reply.agent {
        return Err(Error::InvalidConfig(
            "a connector reply comes from the agent the event addressed".to_owned(),
        ));
    }
    if reply.reply_ref.trim().is_empty() || reply.content_ref.trim().is_empty() {
        return Err(Error::InvalidConfig(
            "a connector reply names its reply and its content".to_owned(),
        ));
    }
    let identity = origin.receiving_identity()?;
    let logical = connector_reply_ref(event, reply);
    let draft = OutboundIntentDraft::new(
        reply.agent.to_hex(),
        reply.verb.clone(),
        origin.channel.clone(),
        origin.source.user_ref.clone(),
    )
    .content_ref(reply.content_ref.clone())
    .idempotency_key(logical.clone())
    .dedupe_key(logical.clone());
    let intent = OutboundIntent::from_trigger(
        draft,
        OutboundIntentTrigger::agent_immediate(event.event_id.clone()),
    );
    let mut request = OutboundDispatchRequest::new(
        logical.clone(),
        logical.clone(),
        intent,
        OutboundDispatchActor::agent(reply.agent),
        OutboundDispatchGate::allow_when_policy_grants(),
        reply.occurred_at,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .channel_identity_ref(identity)
    // An answer to an inbound message is a plain chat message on its own
    // thread, not an interrupt: LINE's compatibility `send` included. The
    // live delivery-window claims still decide at the door.
    .delivery_window_resolved_level(DeliveryWindowResolvedLevel::PlainChat);
    if let SurfaceCounterpartyStamp::Known { counterparty_ref } = &origin.counterparty {
        request = request.counterparty_ref(counterparty_ref.clone());
    }
    // A reply on a pinned thread speaks as the thread's pin (OF-272).
    if let Some(thread) = &origin.thread_ref {
        request = request.reply_thread(thread.clone());
    }
    request.ledger_identity_ref = Some(logical);
    Ok(ConnectorReplyDispatch {
        request,
        thread_ref: origin.thread_ref,
    })
}

/// The stable logical-send ref of one reply to one event.
fn connector_reply_ref(event: &ConnectorEvent, reply: &ConnectorReply) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron.connector-reply.v1\0");
    for value in [
        event.event_id.as_bytes(),
        reply.agent.as_bytes().as_slice(),
        reply.reply_ref.as_bytes(),
    ] {
        hasher.update(&(value.len() as u64).to_be_bytes());
        hasher.update(value);
    }
    format!("connector-reply:{}", hasher.finalize().to_hex())
}

impl Vault {
    /// Sends a host-validated agent reply to a surface-born connector event
    /// through the ordinary recorded dispatch: gate, budget, window, intent
    /// ledger and receipt all apply. The sink is built by the host for the
    /// thread [`connector_reply_request`] names.
    ///
    /// # Errors
    /// The reply does not map onto its event, or dispatch fails.
    pub fn dispatch_connector_reply<S: OutboundExecutionSink>(
        &self,
        event: &ConnectorEvent,
        reply: &ConnectorReply,
        sink: &mut S,
    ) -> std::result::Result<OutboundDispatchResult, OutboundDispatchError> {
        let ConnectorReplyDispatch { request, .. } = connector_reply_request(event, reply)?;
        self.dispatch_outbound_intent_recorded(request, sink)
    }
}
