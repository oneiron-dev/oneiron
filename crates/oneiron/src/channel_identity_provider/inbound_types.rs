//! Shared provider envelope: inbound payload structs, provision result, and the adapter trait.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::channel_identity::ChannelIdentityFulfillment;
use crate::channel_identity_lifecycle::{
    ChannelIdentityFulfillmentInput, ChannelIdentityLifecycleActor, ChannelIdentityLifecycleVerb,
    ProvisionIntent,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::surface_event::InboundSurfaceEventInput;

/// Provider-normalized inbound payload before engine routing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "channel", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ChannelIdentityProviderInbound {
    Email(EmailProviderInbound),
    Slack(SlackProviderInbound),
    Line(LineOfficialAccountInbound),
}

#[doc(hidden)]
pub use oneiron_records::channel_identity_provider::inbound_types::{
    EMAIL_ATTRIBUTION_COLONS, EMAIL_QUOTE_MARKERS, EMAIL_REPLY_TOP_TEXT_MAX_BYTES,
    EMAIL_SIGNATURE_DELIMITER, EmailThreadHeaders, LineChat, LineChatKind,
    LineOfficialAccountInbound, SlackProviderInbound,
};
#[doc(hidden)]
use oneiron_records::channel_identity_provider::inbound_types::{
    EMAIL_CLIENT_SIGNOFFS, email_reply_top_text, is_email_attribution_line,
};

/// Email webhook payload fields the adapter needs for fail-closed routing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailProviderInbound {
    pub provider_event_id: String,
    pub envelope_to: String,
    pub envelope_from: String,
    /// Optional host-parsed Gmail header result. Other email providers leave
    /// this absent and use `envelope_from` as their sender address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_mailbox: Option<super::gmail::HeaderMailbox>,
    /// Threading headers, when the host parsed them. Ingress with them takes
    /// the named-address door (`Vault::enqueue_inbound_email`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_headers: Option<EmailThreadHeaders>,
    /// The `Subject` header as the provider decoded it, when it read one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// The reply's own words: the trimmed top of its decoded plain-text body,
    /// above its first quoted block or signature and without trailing client
    /// sign-offs, cut to [`EMAIL_REPLY_TOP_TEXT_MAX_BYTES`]; absent when the
    /// provider read no body or the body holds nothing above its quote. What
    /// the sender wrote: foreign inbound data, never instructions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_top_text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_ref: Option<String>,
    pub received_at: u64,
}

impl EmailProviderInbound {
    /// Builds an inbound email provider payload.
    #[must_use]
    pub fn new(
        provider_event_id: impl Into<String>,
        envelope_to: impl Into<String>,
        envelope_from: impl Into<String>,
        received_at: u64,
    ) -> Self {
        Self {
            provider_event_id: provider_event_id.into(),
            envelope_to: envelope_to.into(),
            envelope_from: envelope_from.into(),
            header_mailbox: None,
            thread_headers: None,
            subject: None,
            reply_top_text: None,
            payload_ref: None,
            received_at,
        }
    }

    /// Attaches the host-parsed threading headers.
    #[must_use]
    pub fn with_thread_headers(mut self, headers: EmailThreadHeaders) -> Self {
        self.thread_headers = Some(headers);
        self
    }

    /// Attaches a typed From-header projection supplied by the Gmail wire.
    #[must_use]
    pub fn with_header_mailbox(mut self, header_mailbox: super::gmail::HeaderMailbox) -> Self {
        self.header_mailbox = Some(header_mailbox);
        self
    }

    /// Attaches an adapter-local payload reference.
    #[must_use]
    pub fn with_payload_ref(mut self, payload_ref: impl Into<String>) -> Self {
        self.payload_ref = Some(payload_ref.into());
        self
    }

    /// Attaches what the reply says in its own words: its decoded subject,
    /// and the top text of its decoded plain-text body
    /// ([`Self::reply_top_text`]).
    #[must_use]
    pub fn with_reply_text(mut self, subject: Option<String>, text_body: Option<&str>) -> Self {
        self.subject = subject;
        self.reply_top_text = text_body
            .map(|body| {
                let top = email_reply_top_text(body).trim();
                top[..top.floor_char_boundary(EMAIL_REPLY_TOP_TEXT_MAX_BYTES)].to_owned()
            })
            .filter(|top| !top.is_empty());
        self
    }
}

/// Provider result that can be reported back through CID-2 fulfillment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelIdentityProviderProvision {
    pub provider_key: String,
    pub identity_id: EntityId,
    pub channel: String,
    pub address_or_handle: String,
    pub fulfillment_mode: ChannelIdentityFulfillment,
    pub provider_identity_ref: String,
    pub fulfilled_at: u64,
}

impl ChannelIdentityProviderProvision {
    /// Converts provider success into the CID-2 fulfillment input.
    #[must_use]
    pub fn fulfillment_input(
        &self,
        actor: ChannelIdentityLifecycleActor,
    ) -> ChannelIdentityFulfillmentInput {
        ChannelIdentityFulfillmentInput {
            actor,
            identity_id: self.identity_id,
            fulfilled_at: self.fulfilled_at,
        }
    }
}

/// Host-side adapter contract for fulfilling identity lifecycle work.
pub trait ChannelIdentityProviderAdapter {
    /// Stable provider key for receipts, host logs, and adapter selection.
    fn provider_key(&self) -> &'static str;

    /// Declares how this adapter fulfills a lifecycle verb.
    fn fulfillment_mode(
        &self,
        verb: ChannelIdentityLifecycleVerb,
    ) -> Option<ChannelIdentityFulfillment>;

    /// Fulfills a CID-2 ProvisionIntent and returns the state-transition input.
    fn provision(
        &self,
        intent: &ProvisionIntent,
        fulfilled_at: u64,
    ) -> Result<ChannelIdentityProviderProvision>;

    /// Parses provider inbound webhook data into engine SurfaceEvent input.
    fn parse_inbound(
        &self,
        inbound: ChannelIdentityProviderInbound,
    ) -> Result<InboundSurfaceEventInput>;
}
