//! Typed Gmail From-header projection and message metadata.

use super::gmail::{
    GMAIL_EVENT_ID_PREFIX, GMAIL_THREAD_PAYLOAD_PREFIX, MAX_GMAIL_MESSAGE_ID_BYTES,
    MAX_GMAIL_THREAD_ID_BYTES, validate_gmail_id,
};
use super::{EmailProviderInbound, validate_email_inbound_metadata};
use crate::channel_identity::MailboxAddr;
use crate::error::Result;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use sha2::{Digest, Sha256};

/// Gmail's typed result for projecting a `From` header to one mailbox.
///
/// A host with a real RFC 5322 parser should provide [`Self::Parsed`] with its
/// extracted addr-spec. If projection fails, retain only a digest of the raw
/// header in [`Self::Unparsed`]. A parse gap is sender metadata, not a reason to
/// drop the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderMailbox {
    /// The host parser projected and normalized one mailbox address.
    Parsed(MailboxAddr),
    /// The host parser could not project a mailbox; raw header bytes are not retained.
    Unparsed { raw_hash: [u8; 32] },
}

impl HeaderMailbox {
    /// Builds an unparsed result from raw header bytes without retaining them.
    #[must_use]
    pub fn unparsed(raw_header: impl AsRef<[u8]>) -> Self {
        Self::Unparsed {
            raw_hash: Sha256::digest(raw_header.as_ref()).into(),
        }
    }

    fn from_addr_spec_or_unparsed(raw: &str) -> Self {
        MailboxAddr::parse_addr_spec(raw).map_or_else(|_| Self::unparsed(raw), Self::Parsed)
    }
}

impl From<&str> for HeaderMailbox {
    fn from(raw: &str) -> Self {
        Self::from_addr_spec_or_unparsed(raw)
    }
}

impl From<String> for HeaderMailbox {
    fn from(raw: String) -> Self {
        Self::from(raw.as_str())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum HeaderMailboxSerde {
    Parsed { addr_spec: String },
    Unparsed { raw_hash: [u8; 32] },
}

impl Serialize for HeaderMailbox {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Parsed(mailbox) => HeaderMailboxSerde::Parsed {
                addr_spec: mailbox.to_addr_spec(),
            }
            .serialize(serializer),
            Self::Unparsed { raw_hash } => HeaderMailboxSerde::Unparsed {
                raw_hash: *raw_hash,
            }
            .serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for HeaderMailbox {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match HeaderMailboxSerde::deserialize(deserializer)? {
            HeaderMailboxSerde::Parsed { addr_spec } => MailboxAddr::parse_addr_spec(&addr_spec)
                .map(Self::Parsed)
                .map_err(D::Error::custom),
            HeaderMailboxSerde::Unparsed { raw_hash } => Ok(Self::Unparsed { raw_hash }),
        }
    }
}

/// One Gmail message projected down to what routing needs.
///
/// Deliberately header-shaped: the adapter never carries body text into the
/// engine, only the identifiers and envelope needed to route and to point back
/// at the provider-held message. The host owns RFC 5322 parsing at the wire
/// boundary and supplies a typed [`HeaderMailbox`] result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GmailMessageMetadata {
    pub message_id: String,
    pub thread_id: String,
    pub to: String,
    pub from: HeaderMailbox,
    pub internal_date_secs: u64,
}

impl GmailMessageMetadata {
    /// Builds a Gmail message projection.
    ///
    /// String inputs are treated as bare addr-specs. Full header parsing belongs
    /// to the host wire; when a string is not a bare addr-spec it is stored only
    /// as an unparsed-header digest. Hosts with a real parser can pass
    /// [`HeaderMailbox::Parsed`] directly.
    #[must_use]
    pub fn new(
        message_id: impl Into<String>,
        thread_id: impl Into<String>,
        to: impl Into<String>,
        from: impl Into<HeaderMailbox>,
        internal_date_secs: u64,
    ) -> Self {
        Self {
            message_id: message_id.into(),
            thread_id: thread_id.into(),
            to: to.into(),
            from: from.into(),
            internal_date_secs,
        }
    }

    /// Normalizes Gmail-native fields into the shared email inbound payload.
    ///
    /// Gmail's message id becomes the provider event id and its thread id the
    /// payload ref, so the delegated path reaches routing in exactly the same
    /// envelope a dedicated ESP webhook does.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when either id is blank, over the ceiling its
    /// namespaced form leaves, or itself namespaced.
    pub fn into_provider_inbound(self) -> Result<EmailProviderInbound> {
        validate_gmail_id(
            &self.message_id,
            MAX_GMAIL_MESSAGE_ID_BYTES,
            "gmail message id",
        )?;
        validate_gmail_id(
            &self.thread_id,
            MAX_GMAIL_THREAD_ID_BYTES,
            "gmail thread id",
        )?;
        let message_id = self.message_id;
        let thread_id = self.thread_id;
        let envelope_from = match &self.from {
            HeaderMailbox::Parsed(mailbox) => mailbox.to_addr_spec(),
            HeaderMailbox::Unparsed { .. } => String::new(),
        };
        let inbound = EmailProviderInbound::new(
            format!("{GMAIL_EVENT_ID_PREFIX}{message_id}"),
            self.to,
            envelope_from,
            self.internal_date_secs,
        )
        .with_payload_ref(format!("{GMAIL_THREAD_PAYLOAD_PREFIX}{thread_id}"))
        .with_header_mailbox(self.from);
        validate_email_inbound_metadata(&inbound)?;
        Ok(inbound)
    }
}
