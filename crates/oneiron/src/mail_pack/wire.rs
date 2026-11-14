//! The provider seam of the mail importer: what a host's mail wire answers
//! for one connected source. A wire speaks the provider's API (Gmail first,
//! FIX 12559 row 1); the importer ([`super::importer`]) decides what lands.
//! A wire never holds a token past one call and never returns one: it reads
//! the source's credential at its own door, from the custody record the
//! source names.

use serde::{Deserialize, Serialize};

use super::quota::{MailCall, MailQuota};
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
    /// The copy setting's cutoff for this step: mail received before it is
    /// not copied. `None` keeps all mail.
    pub newer_than: Option<u64>,
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
            newer_than: None,
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

#[doc(hidden)]
pub use oneiron_verb_wire::mail_pack::wire::MailAttachmentRef;

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

/// One message's address headers as its raw RFC 5322 source names them,
/// each entry one mailbox, split at the header's top-level commas before
/// any encoded word is decoded (fix list row 20520): a display name whose
/// encoded words decode to a comma or an address stays one quoted name.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MailAddressHeaders {
    pub from: Vec<String>,
    pub reply_to: Vec<String>,
    pub to: Vec<String>,
    pub cc: Vec<String>,
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
    /// A folder or label the provider no longer has: each copied message
    /// under it is looked up again (REVIEW-5754).
    LabelGone { label: String },
    /// A message's labels changed, from a feed that names the labels it
    /// changed, not where the message stands now (Gmail): the importer
    /// reads its headers, one call of the step like any other.
    Relabeled { provider_id: String },
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
/// outside any vault transaction; a read that needs a further request says
/// so ([`MailProviderWire::full_charging`]).
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

    /// [`Self::full`], with `charge` called before each further provider
    /// request the read makes past its first (Gmail reads a text part it
    /// keeps apart by its own request), so a metered step charges every
    /// request before it is made and a refused charge ends the read. By
    /// default the read is one request: [`Self::full`].
    ///
    /// # Errors
    ///
    /// A refused charge, or the provider's own failure.
    fn full_charging(
        &self,
        source: &MailSyncSource,
        provider_id: &str,
        charge: &dyn Fn(MailCall) -> Result<()>,
    ) -> Result<Option<MailFull>> {
        let _ = charge;
        self.full(source, provider_id)
    }

    /// One page of the changes since `anchor`.
    fn history(
        &self,
        source: &MailSyncSource,
        anchor: &str,
        page: Option<&str>,
    ) -> Result<MailHistoryRead>;

    /// The labels a listing read for `provider_id` in this wire's step,
    /// when they come at no further provider read: a provider whose folders
    /// are labels (IMAP) names a message once per folder, so a message the
    /// vault holds carries the folders it is found in, and a listing after
    /// an expired anchor takes them whole where it first names the message
    /// (an empty set where only the all-mail view does). `None` by default.
    fn listed_labels(&self, _provider_id: &str) -> Option<Vec<String>> {
        None
    }

    /// The address headers of `provider_id`, read once from its raw message,
    /// for a reply to it (fix list row 20520). `None` by default: a wire
    /// whose stored headers already hold each address field whole leaves
    /// them to stand. IMAP and mbox land theirs from the whole raw header
    /// block, each mailbox apart (fix list row 20852); Graph names typed
    /// addresses. A wire that answers here never answers `None` for a
    /// message it cannot read.
    ///
    /// # Errors
    ///
    /// The provider's own failure, the message gone at the provider
    /// included.
    fn raw_address_headers(
        &self,
        _source: &MailSyncSource,
        _provider_id: &str,
    ) -> Result<Option<MailAddressHeaders>> {
        Ok(None)
    }

    /// The addresses the provider proves the mailbox owns, as it names them
    /// (fix list row 20400): Gmail's primary and verified send-as addresses,
    /// Graph's `mail` and SMTP proxy addresses. Never one the mailbox only
    /// has a right to send as, a delegate's, or a rewritten address. `None`
    /// by default: a provider that proves none (IMAP, mbox) keeps the
    /// source's stored set. The importer reads a failure here as `None`.
    ///
    /// # Errors
    ///
    /// The provider's own failure, a refusal for a missing scope included.
    fn own_addresses(&self, _source: &MailSyncSource) -> Result<Option<Vec<String>>> {
        Ok(None)
    }

    /// One page of the mailbox's messages that `query` finds, in the
    /// provider's own search language, at most `limit`, trash, spam and
    /// drafts excluded (fix list row 15424). A wire whose provider it cannot
    /// search refuses.
    ///
    /// # Errors
    ///
    /// `mail_search_not_served` from a wire that cannot search, or the
    /// provider's own failure.
    fn search_page(
        &self,
        _source: &MailSyncSource,
        _query: &str,
        _limit: u32,
        _page: Option<&str>,
    ) -> Result<MailIdPage> {
        Err(super::rest::refused("mail_search_not_served"))
    }

    /// Whether a backslash inside a quoted string of this provider's search
    /// language escapes the character after it (IMAP), so a search query's
    /// grouping is read as the provider reads it (fix list row 19089). No by
    /// default: a quote then always ends the string.
    fn search_escapes(&self) -> bool {
        false
    }

    /// One attachment's bytes, as a reader opened it; `None` when the
    /// provider no longer has the message or the attachment.
    fn attachment(
        &self,
        source: &MailSyncSource,
        provider_id: &str,
        attachment: &MailAttachmentRef,
    ) -> Result<Option<Vec<u8>>>;

    /// [`Self::attachment`], with `charge` called before each provider
    /// request the read makes, its first included: the request that finds
    /// an attachment is not always its attachment read (Gmail reads the
    /// whole message for one that rides inline in its part), so a metered
    /// step charges each request as what it is, and a refused charge ends
    /// the read. By default the read is one attachment read, charged before
    /// it is made.
    ///
    /// # Errors
    ///
    /// A refused charge, or the provider's own failure.
    fn attachment_charging(
        &self,
        source: &MailSyncSource,
        provider_id: &str,
        attachment: &MailAttachmentRef,
        charge: &dyn Fn(MailCall) -> Result<()>,
    ) -> Result<Option<Vec<u8>>> {
        charge(MailCall::Attachment)?;
        self.attachment(source, provider_id, attachment)
    }

    /// The provider's per-user limits and each call's cost, which one step
    /// of the importer spends within. `None` by default: a wire that
    /// declares none is never charged, and only a rate-limit answer
    /// ([`super::MAIL_WIRE_RATE_LIMITED`]) rests its source.
    fn quota(&self) -> Option<MailQuota> {
        None
    }

    /// The answer bytes this wire has read from its provider so far, failure
    /// answers included: the importer counts each call's against the day's
    /// download cap. 0 by default.
    fn bytes_read(&self) -> u64 {
        0
    }
}
