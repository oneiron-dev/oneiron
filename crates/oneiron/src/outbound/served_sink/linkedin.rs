//! LinkedIn (FIX 1168, 10905): a reply to an inbound LinkedIn message goes
//! out through the LinkedIn connector the owner installed, never by HTTP
//! from here. Each MCP tool the send uses is an admitted installed-tool call
//! for the replying agent, made through the host's connector calls, so the
//! connector's gate, consent and intent ledger see it as every connector
//! send. The verified send around those calls (OF-327 D2) reads the thread
//! before and after `send_message`, and only a message the send named, which
//! the thread shows as the seat's, is delivered.
//!
//! Only a reply sends here: the answered message names the seat it came to
//! and the thread it is answered in.

use super::ServedChannelSink;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
pub(super) use crate::linkedin_connector::{LINKEDIN_CHANNEL, LINKEDIN_SEND_DM_VERB};
use crate::linkedin_connector::{
    LinkedInConnectorCallTransport, LinkedInMcpConnectorAdapter, LinkedInMcpVerifiedSendSink,
    LinkedInVerifiedSendPlan, linkedin_thread_id_from_key,
};
use crate::outbound::{
    OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink, OutboundIntentSource,
};
use crate::surface_event::SurfaceConnectorPayload;

impl ServedChannelSink<'_> {
    pub(super) fn linkedin_send(
        &self,
        request: &OutboundExecutionRequest<'_>,
    ) -> OutboundExecutionOutcome {
        let Some(text) = self.text(request) else {
            return OutboundExecutionOutcome::failed("content_unresolvable");
        };
        let Some(origin) = self.answered_linkedin_message(request) else {
            return OutboundExecutionOutcome::failed("linkedin_reply_origin_unavailable");
        };
        let Some(thread_id) = linkedin_thread_id_from_key(&request.intent.target) else {
            return OutboundExecutionOutcome::failed("linkedin_target_unrecognized");
        };
        let Some(calls) = self.transports.connector_calls() else {
            return OutboundExecutionOutcome::failed("linkedin_connector_calls_unavailable");
        };
        let Ok(agent) = EntityId::from_hex(&request.intent.actor) else {
            return OutboundExecutionOutcome::failed("linkedin_sender_unrecognized");
        };
        let adapter = match seat_adapter(&origin) {
            Ok(adapter) => adapter,
            Err(error) => {
                tracing::info!(%error, "the answered LinkedIn seat is unreadable");
                return OutboundExecutionOutcome::failed("linkedin_seat_unrecognized");
            }
        };
        let transport = match LinkedInConnectorCallTransport::installed(
            self.vault,
            calls,
            agent,
            EdgeActorClass::Agent,
            &adapter,
        ) {
            Ok(transport) => transport,
            Err(error) => {
                tracing::info!(%error, "no LinkedIn connector serves the reply");
                return OutboundExecutionOutcome::failed("linkedin_connector_not_installed");
            }
        };
        // The plan names the counterparty the Gate admitted, so the verified
        // send's own target check holds.
        let recipient = request.counterparty_ref.unwrap_or(&request.intent.target);
        let sink = LinkedInVerifiedSendPlan::new(recipient, &thread_id, text).and_then(|plan| {
            LinkedInMcpVerifiedSendSink::new(adapter, transport).with_plan(request.intent_ref, plan)
        });
        match sink {
            Ok(mut sink) => sink.execute(request),
            Err(error) => {
                tracing::info!(%error, "the LinkedIn reply has no sendable plan");
                OutboundExecutionOutcome::failed("linkedin_send_plan_invalid")
            }
        }
    }

    /// The surface-born LinkedIn message this send answers: the intent's
    /// trigger names the connector event, which froze the seat and the
    /// thread. `None` when the send answers no LinkedIn message, or one not
    /// this send's target's.
    fn answered_linkedin_message(
        &self,
        request: &OutboundExecutionRequest<'_>,
    ) -> Option<SurfaceConnectorPayload> {
        let intent = request.intent;
        if intent.intent_source != OutboundIntentSource::AgentImmediate.as_str() {
            return None;
        }
        let agent = EntityId::from_hex(&intent.actor).ok()?;
        let event = match self.vault.connector_event_woken(agent, &intent.trigger_ref) {
            Ok(event) => event?,
            Err(error) => {
                tracing::info!(%error, "the answered LinkedIn event is unreadable");
                return None;
            }
        };
        let origin = SurfaceConnectorPayload::from_connector_event(&event).ok()?;
        (origin.channel == LINKEDIN_CHANNEL && origin.reply_target() == intent.target)
            .then_some(origin)
    }
}

/// The seat the answered message came to, on the session it was read
/// through.
fn seat_adapter(origin: &SurfaceConnectorPayload) -> crate::Result<LinkedInMcpConnectorAdapter> {
    let adapter = LinkedInMcpConnectorAdapter::new(origin.receiving_address_or_handle.clone())?;
    match &origin.workspace_ref {
        Some(session_ref) => adapter.with_session_ref(session_ref.clone()),
        None => Ok(adapter),
    }
}
