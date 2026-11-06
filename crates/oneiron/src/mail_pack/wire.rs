//! The provider seam of the mail importer: what a host's mail wire answers
//! for one connected source. A wire speaks the provider's API (Gmail first,
//! FIX 12559 row 1); the importer ([`super::importer`]) decides what lands.
//! A wire never holds a token past one call and never returns one: it reads
//! the source's credential at its own door, from the custody record the
//! source names.

use serde::{Deserialize, Serialize};

use super::source::{MailProvider, MailSourceRow};
use crate::{EntityId, Result};

/// What a wire is told about the source it reads: its identity and the
/// custody record its credential is stored under, never the credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailSyncSource {
    pub source_ref: EntityId,
    pub provider: MailProvider,
    /// The mailbox or group address.
    pub address: String,
    /// The provider's stable account id.
    pub provider_account: String,
    /// The custody record the credential is stored under.
    pub custody_ref: String,
    /// The delegated channel identity the source reads through, if any.
    pub channel_identity: Option<EntityId>,
}

impl MailSyncSource {
    pub(super) fn of(source_ref: EntityId, row: &MailSourceRow) -> Self {
        Self {
            source_ref,
            provider: row.provider,
            address: row.address.clone(),
            provider_account: row.provider_account.clone(),
            custody_ref: row.custody_ref.clone(),
            channel_identity: row.channel_identity,
        }
    }
}

/// One message a listing or a history page names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailMessageRef {
    /// The provider's id for the message in this mailbox (Gmail `id`).
    pub provider_id: String,
    /// The provider's thread id (Gmail `threadId`), when it has one.
    pub thread_id: Option<String>,
}

/// What a listing asks for: newest first, trash and spam never, and for a
/// source keeping its recent months only, nothing older than `newer_than`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MailListQuery {
    /// Unix seconds: list only messages received at or after it.
    pub newer_than: Option<u64>,
}

/// One page of a newest-first listing.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MailIdPage {
    pub messages: Vec<MailMessageRef>,
    /// The provider's token for the next, older page; `None` at the end.
    pub next_page: Option<String>,
}

/// One attachment a message carries, as described, not its bytes: bytes
/// load only when someone opens it (MAIL-GOOGLE = A).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailAttachmentRef {
    /// The MIME part id within the message.
    pub part_id: String,
    /// The provider's attachment id, when its bytes are fetched apart.
    pub provider_attachment_id: Option<String>,
    pub filename: Option<String>,
    pub media_type: String,
    pub size_bytes: u64,
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
}

/// One change a history page reports since the source's anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailHistoryChange {
    /// A message arrived in, or was filed into, the mailbox.
    Added(MailMessageRef),
    /// The provider deleted a message for good.
    Deleted { provider_id: String },
    /// A message's labels changed; one moved to trash or spam counts as
    /// deleted at the provider.
    Labels {
        provider_id: String,
        labels: Vec<String>,
        trash_or_spam: bool,
    },
}

/// One page of changes since an anchor.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MailHistoryPage {
    pub changes: Vec<MailHistoryChange>,
    /// The next page of the same read; `None` on the last.
    pub next_page: Option<String>,
    /// The anchor the source stands at once every page of this read is
    /// applied (Gmail's latest `historyId`).
    pub anchor: String,
}

/// What a history read answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailHistoryRead {
    Page(MailHistoryPage),
    /// The provider no longer keeps history from that anchor (Gmail 404): the
    /// importer takes a new anchor and lists the mailbox again. Nothing is
    /// read as deleted for it.
    Expired,
}

/// A host's mail wire for one provider. Each call is one provider read, run
/// outside any vault transaction.
pub trait MailProviderWire {
    /// The provider's current change anchor (Gmail `users.getProfile`
    /// `historyId`), taken before a listing starts so no change made during
    /// it is missed.
    fn current_anchor(&self, source: &MailSyncSource) -> Result<String>;

    /// One page of the mailbox's messages, newest first, trash and spam
    /// excluded.
    fn list_page(
        &self,
        source: &MailSyncSource,
        query: &MailListQuery,
        page: Option<&str>,
    ) -> Result<MailIdPage>;

    /// One message's headers; `None` when the provider no longer has it.
    fn headers(&self, source: &MailSyncSource, provider_id: &str) -> Result<Option<MailHeaders>>;

    /// One message whole; `None` when the provider no longer has it.
    fn full(&self, source: &MailSyncSource, provider_id: &str) -> Result<Option<MailFull>>;

    /// One page of the changes since `anchor`.
    fn history(
        &self,
        source: &MailSyncSource,
        anchor: &str,
        page: Option<&str>,
    ) -> Result<MailHistoryRead>;
}
