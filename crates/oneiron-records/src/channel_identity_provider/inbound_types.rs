//! Moved from `crates/oneiron/src/channel_identity_provider/inbound_types.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::fmt;

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

/// The most of an email reply's top text an inbound keeps.
pub const EMAIL_REPLY_TOP_TEXT_MAX_BYTES: usize = 4 * 1024;

/// The lines that open the quoted block of an email reply, each read on a
/// trimmed line as (how it starts, how it ends): a `>` quote line, and an
/// `On <date>, <sender> wrote:` attribution, which a client may wrap onto a
/// second line.
pub const EMAIL_QUOTE_MARKERS: &[(&str, &str)] = &[(">", ""), ("On ", "wrote:")];

/// The signature delimiter line (`-- `, read trimmed): the reply's own text
/// ends above it.
pub const EMAIL_SIGNATURE_DELIMITER: &str = "--";

/// The colons an attribution line ends with in any language, such as
/// `2026年10月31日(土) 10:00 名前 <a@b>:`: a line naming an address in angle
/// brackets and ending with one of these opens the quoted block.
pub const EMAIL_ATTRIBUTION_COLONS: &[char] = &[':', '：'];

/// The mobile client sign-off lines a reply's top text drops from its end,
/// each compared after trimming: a final line that is one of these is not
/// the reply's own words.
pub const EMAIL_CLIENT_SIGNOFFS: &[&str] = &[
    "Sent from my iPhone",
    "Sent from my iPad",
    "Sent from my Android",
    "Get Outlook for iOS",
    "Get Outlook for Android",
    "iPhoneから送信",
    "iPadから送信",
    "Androidから送信",
];

/// Whether `line` (trimmed) attributes the quote below it in any language:
/// it names an address in angle brackets and ends with an attribution colon.
pub fn is_email_attribution_line(line: &str) -> bool {
    line.ends_with(EMAIL_ATTRIBUTION_COLONS)
        && line
            .split_once('<')
            .and_then(|(_, rest)| rest.split_once('>'))
            .is_some_and(|(address, _)| address.contains('@'))
}

/// An email reply's top text: its body above the first line that opens a
/// quoted block ([`EMAIL_QUOTE_MARKERS`], or an attribution line in any
/// language) or its signature ([`EMAIL_SIGNATURE_DELIMITER`]); the whole
/// body when none does. Trailing client sign-offs
/// ([`EMAIL_CLIENT_SIGNOFFS`]) are dropped, with the blank lines around them.
pub fn email_reply_top_text(body: &str) -> &str {
    let mut at = 0;
    let mut lines = body.split_inclusive('\n').peekable();
    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        let wrapped = lines.peek().copied().map(str::trim);
        let opens = EMAIL_QUOTE_MARKERS.iter().any(|&(start, end)| {
            trimmed.starts_with(start)
                && (trimmed.ends_with(end) || wrapped.is_some_and(|next| next.ends_with(end)))
        }) || trimmed == EMAIL_SIGNATURE_DELIMITER
            || is_email_attribution_line(trimmed);
        if opens {
            break;
        }
        at += line.len();
    }
    let mut end = at;
    loop {
        let current = body[..end].trim_end();
        let Some(last) = current.rsplit('\n').next() else {
            return current;
        };
        if !EMAIL_CLIENT_SIGNOFFS.contains(&last.trim()) {
            return current;
        }
        end = current.len() - last.len();
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
    /// The group or room a message was written in when it still routes per
    /// sender (no identity is bound to that chat). It never routes: it is
    /// the audience the reply answers, so a reply is admitted on the chat,
    /// not on whoever wrote (FIX 2838).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_chat: Option<LineChat>,
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
            .field("reply_chat", &self.reply_chat)
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
            reply_chat: None,
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

    /// Names the group or room a per-sender message was written in: the
    /// reply's audience, never its route.
    #[must_use]
    pub fn with_reply_chat(mut self, chat: LineChat) -> Self {
        self.reply_chat = Some(chat);
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
    pub const fn id_lead(self) -> u8 {
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
