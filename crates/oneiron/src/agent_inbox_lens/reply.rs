//! Chosen INBOX replies: one exact message, one caller request, the ordinary
//! connector reply worker and recorded dispatch. Acceptance is not delivery.

use serde::{Deserialize, Serialize};

use super::{AgentInboxItemKind, InboxTextSource};
use crate::EntityId;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::claim::ClaimReadStatus;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::outbound::{CONNECTOR_REPLY_JOB_KIND, ConnectorReplyJob, ConnectorReplyJobResult};
use crate::surface_event::{
    SurfaceConnectorPayload, SurfaceEventAction, SurfaceEventDispatchRoute,
};

/// Replies to the exact message anchor returned by `self.inbox.get`.
/// Retry the same request_ref and text to replay; use a new request_ref for
/// an intentional follow-up, including one with the same words.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InboxReplyRequest {
    pub item_id: String,
    pub event_ref: String,
    pub request_ref: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InboxReplyStatusRequest {
    /// The 32-hex queue attempt returned by `self.inbox.reply`.
    pub job_ref: String,
}

/// A snapshot of the queue and its existing versioned results. `dispatched`
/// is not necessarily delivered: inspect each result's exact `outcome`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxReplyJobStatus {
    pub job_ref: String,
    pub state: String,
    pub results: Vec<ConnectorReplyJobResult>,
}

/// The reply request is durably accepted. Its worker may still be queued,
/// held, failed or ambiguous; this never marks the inbound item Done.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxReplyReceipt {
    pub item_id: String,
    pub event_ref: String,
    pub job: InboxReplyJobStatus,
}

impl Memory<'_> {
    /// Queues the caller's exact words for one readable, addressed message.
    /// The host owns transport; the ordinary live Gate and grant checks run
    /// when its worker dispatches. No new model call chooses the words.
    pub fn inbox_item_reply(&self, input: &InboxReplyRequest) -> MemoryResult<InboxReplyReceipt> {
        let item = self.own_inbox_item(&input.item_id)?;
        if item.kind != AgentInboxItemKind::Conversation {
            return Err(MemoryError::bad_request(
                "this inbox row has no message to reply to",
            ));
        }
        let read = self.read_lane(ClaimReadStatus::Recorded)?;
        let resolved = self
            .vault()
            .resolve_agent_inbox_texts(&read, std::slice::from_ref(&item))?;
        let selected = resolved
            .get(&item.item_id)
            .and_then(|row| {
                row.messages.iter().find(|message| {
                    let InboxTextSource::ProviderEvent {
                        reply_event_ref, ..
                    } = &message.source;
                    reply_event_ref.as_deref() == Some(input.event_ref.as_str())
                })
            })
            .ok_or_else(|| {
                MemoryError::not_found(
                    "no readable reply message with that event anchor is on this inbox row",
                )
            })?;
        let event = self
            .vault()
            .connector_event_woken(self.actor(), &input.event_ref)?
            .ok_or_else(|| MemoryError::not_found("the reply event is no longer held"))?;
        let origin = SurfaceConnectorPayload::from_connector_event(&event)?;
        let InboxTextSource::ProviderEvent {
            channel,
            payload_ref,
            ..
        } = &selected.source;
        if origin.actor()? != self.actor()
            || origin.receiving_identity()? != selected.identity_ref
            || origin.channel != *channel
            || origin.payload_ref.as_deref() != Some(payload_ref.as_str())
            || origin.received_at != selected.occurred_at
            || !matches!(origin.action, SurfaceEventAction::Message)
            || matches!(
                origin.route,
                SurfaceEventDispatchRoute::ObservedSourceEnrichment
            )
        {
            return Err(MemoryError::bad_request(
                "the reply event does not name this addressed message",
            ));
        }
        let attempt = self.vault().enqueue_connector_reply_text(
            self.actor(),
            &event,
            &input.request_ref,
            &input.text,
            self.vault().now_recorded_at(),
        )?;
        Ok(InboxReplyReceipt {
            item_id: item.item_id,
            event_ref: event.event_id,
            job: self.inbox_reply_job_status(attempt)?,
        })
    }

    /// Reads only this actor's existing reply job and versioned results.
    pub fn inbox_reply_status(
        &self,
        input: &InboxReplyStatusRequest,
    ) -> MemoryResult<InboxReplyJobStatus> {
        crate::memory::verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let id = EntityId::from_hex(&input.job_ref)
            .map_err(|_| MemoryError::bad_request("reply job_ref must be 32 hex"))?;
        self.inbox_reply_job_status(AttemptId::from_bytes(id.as_bytes())?)
    }

    fn inbox_reply_job_status(&self, attempt: AttemptId) -> MemoryResult<InboxReplyJobStatus> {
        let record = AttemptQueue::new(self.vault())
            .get(attempt)?
            .filter(|record| record.kind == CONNECTOR_REPLY_JOB_KIND)
            .ok_or_else(|| MemoryError::not_found("no reply job with that reference"))?;
        let job: ConnectorReplyJob = serde_json::from_slice(&record.payload)
            .map_err(|_| MemoryError::not_found("no readable reply job with that reference"))?;
        if job.agent != self.actor() {
            return Err(MemoryError::not_found("no reply job with that reference"));
        }
        Ok(InboxReplyJobStatus {
            job_ref: EntityId::from_bytes(*attempt.as_bytes()).to_hex(),
            state: record.state.as_str().to_owned(),
            results: self.vault().connector_reply_job_results(attempt)?,
        })
    }
}
