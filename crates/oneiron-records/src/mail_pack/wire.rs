//! Moved from `crates/oneiron/src/mail_pack/wire.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::mail_pack::wire::MailAttachmentRef;
use serde::Deserialize;
use serde::Serialize;

/// One message a listing or a history page names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailMessageRef {
    /// The provider's id for the message in this mailbox (Gmail `id`).
    pub provider_id: String,
    /// The provider's thread id (Gmail `threadId`), when it has one.
    pub thread_id: Option<String>,
}

/// A message's headers, as a header stage reads them.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MailHeaders {
    pub provider_id: String,
    pub thread_id: Option<String>,
    /// The RFC 5322 `Message-ID`, angle brackets kept.
    pub rfc_message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    pub from: Option<String>,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    /// The `Reply-To` addresses, where a reply goes when the sender named
    /// one (FIX 15420).
    #[serde(default)]
    pub reply_to: Vec<String>,
    pub subject: Option<String>,
    /// The authored `Date` header, Unix seconds.
    pub date: Option<u64>,
    /// When the provider received or filed it, Unix seconds.
    pub received_at: u64,
    /// The provider's labels or folders (Gmail label ids).
    pub labels: Vec<String>,
    /// Whether the message was sent from this mailbox (Gmail `SENT`).
    pub sent_by_mailbox: bool,
    /// Whether the provider holds it as trash or spam: never ingested.
    pub trash_or_spam: bool,
    /// Whether it is a draft: not mail yet, never ingested.
    pub draft: bool,
}

/// A message read whole: its headers, its plain-text body, and its
/// attachments described.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MailFull {
    pub headers: MailHeaders,
    /// The plain-text body, or the text of an HTML-only body; `None` when the
    /// message has no text part.
    pub body_text: Option<String>,
    pub attachments: Vec<MailAttachmentRef>,
    /// The BLAKE3 of the whole message, each line ended by CRLF, when it was
    /// read whole: what proves a copy of it found later to be the same
    /// message (fix list row 19145). `None` where the wire does not read the
    /// message's bytes.
    #[serde(default)]
    pub content_digest: Option<[u8; 32]>,
}
