//! Gmail (FIX 1168): a send from a member's delegated Gmail row leaves as the
//! member, through the adapter's own [`GmailSendSink`] on the production send
//! wire, with the row's own grant. The sink sends one frozen plan: From is the
//! row's mailbox, To the send's target, the body the typed content's text and
//! the subject its first line, as a native mail send's. The plan is registered
//! under the intent's content ref, which the send's approval binds.
//!
//! A send that answers an inbound Gmail message on the same row joins that
//! message's Gmail thread: In-Reply-To names the latest message the row has on
//! the thread, and References every one, in the order they were observed.

use super::ServedChannelSink;
use super::email::email_subject;
use crate::EntityId;
use crate::channel_identity_provider::EMAIL_CHANNEL;
use crate::channel_identity_provider::gmail::{
    GMAIL_THREAD_PAYLOAD_PREFIX, GmailDelegatedAdapter, GmailReplyThread, GmailSendPlan,
    GmailSendSink, HttpGmailSendWire,
};
use crate::channel_identity_provider::member_mail::is_member_mail_identity_in_txn;
use crate::channel_identity_provider::native_mail::canonical_recipient;
use crate::error::Error;
use crate::outbound::{OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink};
use crate::surface_event::SurfaceConnectorPayload;

/// What the Gmail adapter puts before a sender's address in its counterparty
/// key.
const EMAIL_COUNTERPARTY_PREFIX: &str = "email:";

impl ServedChannelSink<'_> {
    /// Whether the send leaves from a delegated Gmail row.
    pub(super) fn sends_from_gmail(&self, request: &OutboundExecutionRequest<'_>) -> bool {
        let Some(identity) = request.channel_identity_ref else {
            return false;
        };
        self.vault
            .store
            .env
            .read_txn()
            .map_err(Error::from)
            .and_then(|txn| is_member_mail_identity_in_txn(&self.vault.store, &txn, identity))
            .unwrap_or(false)
    }

    pub(super) fn gmail_send(
        &self,
        request: &OutboundExecutionRequest<'_>,
    ) -> OutboundExecutionOutcome {
        let Some(identity) = request.channel_identity_ref else {
            return OutboundExecutionOutcome::failed("email_sender_absent");
        };
        let adapter = match GmailDelegatedAdapter::for_delegated_identity(self.vault, identity) {
            Ok(Some(adapter)) => adapter,
            _ => return OutboundExecutionOutcome::failed("gmail_sender_unreadable"),
        };
        let (Some(content_ref), Some(text)) =
            (request.intent.content_ref.as_deref(), self.text(request))
        else {
            return OutboundExecutionOutcome::failed("content_unresolvable");
        };
        let plan = match GmailSendPlan::new(
            &adapter,
            request.intent_ref,
            &request.intent.target,
            &email_subject(&text),
            &text,
            self.gmail_reply_thread(request, identity),
            crate::unix_seconds_now(),
        ) {
            Ok(plan) => plan,
            Err(_) => return OutboundExecutionOutcome::failed("gmail_send_plan_invalid"),
        };
        let wire = match HttpGmailSendWire::new() {
            Ok(wire) => wire,
            Err(_) => return OutboundExecutionOutcome::failed("gmail_send_client_unavailable"),
        };
        GmailSendSink::new(self.vault, &adapter, identity, wire)
            .with_content_plan(content_ref, plan)
            .execute(request)
    }

    /// The Gmail thread a send answering an inbound Gmail message joins: the
    /// message's own Gmail thread, from its payload ref, after the messages
    /// `identity` has on its passport thread. `None` for a send that answers
    /// no Gmail message from its target to `identity`, or a thread with no
    /// passport on `identity`.
    fn gmail_reply_thread(
        &self,
        request: &OutboundExecutionRequest<'_>,
        identity: EntityId,
    ) -> Option<GmailReplyThread> {
        let origin = self.answered_gmail_origin(request, identity)?;
        let gmail_thread = self.gmail_thread_of(origin.payload_ref.as_deref()?)?;
        let mut passports = match self.vault.thread_passports(origin.thread_ref.as_deref()?) {
            Ok(passports) => passports,
            Err(error) => {
                tracing::info!(%error, "the answered Gmail thread is unreadable");
                return None;
            }
        };
        passports.retain(|passport| passport.identity_ref == identity);
        passports.sort_by_key(|passport| passport.observed_at);
        let parent = passports.last()?;
        let references = passports
            .iter()
            .map(|passport| passport.message_id.as_str())
            .collect::<Vec<_>>();
        GmailReplyThread::new(&gmail_thread, parent.message_id.as_str(), &references).ok()
    }

    /// The Gmail thread id `payload_ref` names. The run door archives each
    /// Gmail inbound as its provider event, so a live ref is the archive's:
    /// the archived body keeps the `gmail:thread:` ref it arrived with.
    fn gmail_thread_of(&self, payload_ref: &str) -> Option<String> {
        if let Some(thread) = payload_ref.strip_prefix(GMAIL_THREAD_PAYLOAD_PREFIX) {
            return Some(thread.to_owned());
        }
        self.vault
            .read_provider_email(payload_ref)
            .ok()?
            .and_then(|email| email.payload_ref)
            .and_then(|kept| {
                kept.strip_prefix(GMAIL_THREAD_PAYLOAD_PREFIX)
                    .map(str::to_owned)
            })
    }

    /// The inbound Gmail message this send answers: the intent's trigger
    /// names the connector event that woke its actor, the event reached
    /// `identity`, and its sender is the send's target.
    fn answered_gmail_origin(
        &self,
        request: &OutboundExecutionRequest<'_>,
        identity: EntityId,
    ) -> Option<SurfaceConnectorPayload> {
        let intent = request.intent;
        let agent = EntityId::from_hex(&intent.actor).ok()?;
        let event = match self.vault.connector_event_woken(agent, &intent.trigger_ref) {
            Ok(event) => event?,
            Err(error) => {
                tracing::info!(%error, "the answered Gmail event is unreadable");
                return None;
            }
        };
        let origin = SurfaceConnectorPayload::from_connector_event(&event).ok()?;
        let sender = origin
            .reply_target()
            .strip_prefix(EMAIL_COUNTERPARTY_PREFIX)
            .and_then(|sender| canonical_recipient(sender).ok())?;
        let answers = origin.channel == EMAIL_CHANNEL
            && EntityId::from_hex(&origin.receiving_identity_ref).ok() == Some(identity)
            && canonical_recipient(&intent.target).ok().as_ref() == Some(&sender);
        answers.then_some(origin)
    }
}
