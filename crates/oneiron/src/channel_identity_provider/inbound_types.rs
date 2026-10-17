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

/// RFC 5322 threading headers the host parsed at the wire. They join the mail
/// to its thread through the passport graph (R5), whichever identity got it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailThreadHeaders {
    /// The `Message-ID` header, with or without its angle brackets.
    pub message_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
}

impl EmailThreadHeaders {
    /// Builds the header set of one message.
    #[must_use]
    pub fn new(
        message_id: impl Into<String>,
        references: Vec<String>,
        in_reply_to: Option<String>,
    ) -> Self {
        Self {
            message_id: message_id.into(),
            references,
            in_reply_to,
        }
    }
}

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
}

/// Slack Events API payload fields needed for shared-presence routing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlackProviderInbound {
    pub provider_event_id: String,
    pub workspace_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enterprise_id: Option<String>,
    pub channel_id: String,
    pub user_id: String,
    pub persona_handle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_ref: Option<String>,
    pub received_at: u64,
}

impl SlackProviderInbound {
    /// Builds a Slack inbound event after the host has resolved the persona.
    #[must_use]
    pub fn new(
        provider_event_id: impl Into<String>,
        workspace_id: impl Into<String>,
        channel_id: impl Into<String>,
        user_id: impl Into<String>,
        persona_handle: impl Into<String>,
        received_at: u64,
    ) -> Self {
        Self {
            provider_event_id: provider_event_id.into(),
            workspace_id: workspace_id.into(),
            enterprise_id: None,
            channel_id: channel_id.into(),
            user_id: user_id.into(),
            persona_handle: persona_handle.into(),
            payload_ref: None,
            received_at,
        }
    }

    /// Attaches an Enterprise Grid org id when Slack supplies one.
    #[must_use]
    pub fn with_enterprise_id(mut self, enterprise_id: impl Into<String>) -> Self {
        self.enterprise_id = Some(enterprise_id.into());
        self
    }

    /// Attaches an adapter-local payload reference.
    #[must_use]
    pub fn with_payload_ref(mut self, payload_ref: impl Into<String>) -> Self {
        self.payload_ref = Some(payload_ref.into());
        self
    }
}

/// LINE Messaging API webhook event fields used by the adapter.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineOfficialAccountInbound {
    pub provider_event_id: String,
    /// LINE webhook `destination` value for the product OA.
    pub destination: String,
    /// Provider-native LINE user id from the event source. LINE leaves it
    /// out of some group and room messages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_user_id: Option<String>,
    /// The group or room this message routes by: set when it goes to that
    /// chat's own identity rather than its sender's. `None` routes per
    /// sender, as a 1:1 message does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chat: Option<LineChat>,
    #[serde(default, skip_serializing)]
    pub reply_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_ref: Option<String>,
    pub received_at: u64,
}

impl fmt::Debug for LineOfficialAccountInbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LineOfficialAccountInbound")
            .field("provider_event_id", &self.provider_event_id)
            .field("destination", &self.destination)
            .field("source_user_id", &self.source_user_id)
            .field("chat", &self.chat)
            .field(
                "reply_token",
                &self.reply_token.as_ref().map(|_| "[redacted]"),
            )
            .field("payload_ref", &self.payload_ref)
            .field("received_at", &self.received_at)
            .finish()
    }
}

impl LineOfficialAccountInbound {
    /// Builds a LINE OA webhook event payload.
    #[must_use]
    pub fn new(
        provider_event_id: impl Into<String>,
        destination: impl Into<String>,
        source_user_id: impl Into<String>,
        received_at: u64,
    ) -> Self {
        Self {
            provider_event_id: provider_event_id.into(),
            destination: destination.into(),
            source_user_id: Some(source_user_id.into()),
            chat: None,
            reply_token: None,
            payload_ref: None,
            received_at,
        }
    }

    /// Attaches the provider reply token without exposing it to SurfaceEvent stamps.
    #[must_use]
    pub fn with_reply_token(mut self, reply_token: impl Into<String>) -> Self {
        self.reply_token = Some(reply_token.into());
        self
    }

    /// Attaches an adapter-local payload reference.
    #[must_use]
    pub fn with_payload_ref(mut self, payload_ref: impl Into<String>) -> Self {
        self.payload_ref = Some(payload_ref.into());
        self
    }

    /// Routes the message by its group or room's own identity.
    #[must_use]
    pub fn with_chat(mut self, chat: LineChat) -> Self {
        self.chat = Some(chat);
        self
    }
}

/// The kind of LINE chat a shared message came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LineChatKind {
    /// A LINE group (`source.groupId`, `C…`).
    Group,
    /// A multi-person room (`source.roomId`, `R…`).
    Room,
}

impl LineChatKind {
    /// The `source.type` LINE names this kind by, and the address segment.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Group => "group",
            Self::Room => "room",
        }
    }

    /// Parses a LINE `source.type`; `None` for a 1:1 `user` or anything else.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "group" => Some(Self::Group),
            "room" => Some(Self::Room),
            _ => None,
        }
    }

    /// The `source` field that names a chat of this kind.
    #[must_use]
    pub const fn id_field(self) -> &'static str {
        match self {
            Self::Group => "groupId",
            Self::Room => "roomId",
        }
    }

    /// The leading byte of a LINE id of this kind.
    pub(super) const fn id_lead(self) -> u8 {
        match self {
            Self::Group => b'C',
            Self::Room => b'R',
        }
    }
}

/// One LINE group or room, by its provider id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineChat {
    pub kind: LineChatKind,
    pub id: String,
}

impl LineChat {
    #[must_use]
    pub fn new(kind: LineChatKind, id: impl Into<String>) -> Self {
        Self {
            kind,
            id: id.into(),
        }
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
