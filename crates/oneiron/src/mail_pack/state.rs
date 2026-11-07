//! What the importer keeps per source and per provider message: where its
//! listing and its change feed stand, and each message's rows, stage and
//! presence at the provider. The four ids stay apart (MAIL-GOOGLE = A): the
//! Oneiron rows, the provider's id (the key here), the RFC `Message-ID`
//! with the content hash, and the provider's thread id.

use serde::{Deserialize, Serialize};

use super::source::MailCopySetting;
use super::wire::MailAttachmentRef;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

/// One source's sync state, by the source.
pub(super) const SYNC: SideTable<EntityId, MailSyncState, Named> =
    SideTable::new(&side_table::MAIL_PACK_SYNC);
/// One provider message of one source, by the source and the BLAKE3 of the
/// provider's message id.
pub(super) const OCCURRENCES: SideTable<(EntityId, [u8; 32]), MailOccurrence, Named> =
    SideTable::new(&side_table::MAIL_PACK_OCCURRENCE);
/// The messages that landed with their headers only and wait for their
/// bodies, newest first: by the source, `u64::MAX` less the receive time,
/// and the BLAKE3 of the provider's id. The value is the provider's id.
pub(super) const BODY_QUEUE: SideTable<(EntityId, u64, [u8; 32]), String, Named> =
    SideTable::new(&side_table::MAIL_PACK_BODY_QUEUE);
/// The header-only revisions a later body superseded, each owed its delete
/// (FIX 15413): by the source, the BLAKE3 of the provider's id and the
/// revision's MESSAGE. The value is when it was owed. A row leaves once the
/// MESSAGE's delete returns.
pub(super) const HEADER_RETIREMENTS: SideTable<(EntityId, [u8; 32], EntityId), u64, Named> =
    SideTable::new(&side_table::MAIL_PACK_HEADER_RETIREMENT);
/// How many times each thread's CONVERSATION was forgotten whole, by the
/// source and the BLAKE3 of the thread key ([`thread_hash`]): a message
/// landing in the thread afterwards opens a new CONVERSATION, never the one
/// forgotten (fix list row 18084).
pub(super) const THREAD_EPOCHS: SideTable<(EntityId, [u8; 32]), u64, Named> =
    SideTable::new(&side_table::MAIL_PACK_THREAD_EPOCH);
/// The rows each provider message landed as, so an erase of any of them
/// reaches the message: by the row (its CONVERSATION, TURN or a MESSAGE
/// revision), the source and the BLAKE3 of the provider's id. The value is
/// when it was recorded.
const OCCURRENCE_ROWS: SideTable<(EntityId, EntityId, [u8; 32]), u64, Named> =
    SideTable::new(&side_table::MAIL_PACK_OCCURRENCE_ROW);

/// Where one source's import stands.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub(super) struct MailSyncState {
    /// The provider's change anchor the source stands at (Gmail
    /// `historyId`); changes after it are read from the change feed.
    pub(super) anchor: Option<String>,
    /// The newest-first listing's next page; `None` before the first page
    /// and once it is done.
    pub(super) backfill_page: Option<String>,
    /// Whether the listing reached the oldest message it copies.
    pub(super) backfill_done: bool,
    /// The cutoff the listing runs under (recent months), so a changed
    /// setting starts it over.
    pub(super) backfill_newer_than: Option<u64>,
    /// The copy setting the listing runs under; a changed setting, or
    /// `None` after an expired anchor, starts it over with a fresh cutoff.
    #[serde(default)]
    pub(super) backfill_copy: Option<MailCopySetting>,
    /// Bumped each time the listing starts over (an expired anchor, a
    /// changed copy setting).
    pub(super) generation: u64,
    /// The change feed's next page, read from `history_page_anchor`: a feed
    /// longer than one step's budget goes on from it at the next step.
    #[serde(default)]
    pub(super) history_page: Option<String>,
    #[serde(default)]
    pub(super) history_page_anchor: Option<String>,
    pub(super) landed: u64,
    pub(super) bodies: u64,
    pub(super) deleted_at_provider: u64,
    pub(super) last_step_at: Option<u64>,
    /// The last step's failure, in words, for the source's owner.
    pub(super) last_error: Option<String>,
    /// The listing begun after an expired anchor: once it completes, a live
    /// copy it never named, landed before it began, was deleted at the
    /// provider meanwhile (fix list row 17937).
    #[serde(default)]
    pub(super) relist: Option<MailRelist>,
}

/// A listing that settles the copies an expired anchor lost track of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct MailRelist {
    /// The listing's generation ([`MailSyncState::generation`]).
    pub(super) generation: u64,
    /// When it began: a copy landed since came through it or the feed.
    pub(super) since: u64,
}

/// How much of a message has landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MailStage {
    /// Its headers: it is searchable by sender, recipients and subject.
    Headers,
    /// Its body too.
    Body,
}

/// Whether the provider still holds a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MailPresence {
    Present,
    /// Deleted at the provider, kept as a labelled source-deleted copy (the
    /// source's "keep in memory" setting): out of the live inbox, still in
    /// the vault.
    SourceDeleted {
        at: u64,
    },
    /// Deleted at the provider and forgotten in the vault too (the source's
    /// "forget too" setting). The row stays as a fence: a later listing does
    /// not bring the message back.
    Forgotten {
        at: u64,
    },
}

/// One provider message of one source and the rows it landed as.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct MailOccurrence {
    pub(super) provider_id: String,
    pub(super) thread_key: String,
    pub(super) conversation: EntityId,
    pub(super) turn: EntityId,
    /// Each revision's MESSAGE, oldest first: the headers, then the whole
    /// message.
    pub(super) messages: Vec<EntityId>,
    /// Each revision's content hash, in the same order.
    pub(super) content_hashes: Vec<String>,
    pub(super) stage: MailStage,
    pub(super) presence: MailPresence,
    pub(super) labels: Vec<String>,
    pub(super) rfc_message_id: Option<String>,
    /// The sender and subject, as the inbox lists the message.
    pub(super) from: Option<String>,
    pub(super) subject: Option<String>,
    pub(super) received_at: u64,
    /// Whether a search fetched it: kept whatever the copy setting.
    pub(super) searched: bool,
    /// Its attachments, as its whole message described them; empty until
    /// its body lands.
    #[serde(default)]
    pub(super) attachments: Vec<MailAttachmentRef>,
    /// The headers a reply to it is built from, whole (FIX 15420); `None`
    /// for a message landed before replies were drafted, or forgotten.
    #[serde(default)]
    pub(super) reply: Option<MailReplyHeaders>,
    /// The generation of the last listing that named it (fix list row
    /// 17937); `None` before a listing after an expired anchor did.
    #[serde(default)]
    pub(super) listed_in: Option<u64>,
    /// The BLAKE3 of its whole message, each line ended by CRLF, from the
    /// first time it landed whole (the live body stage or an mbox import);
    /// `None` until then. An IMAP copy proposing this id is this message
    /// only when its own digest is the same (fix list row 19145).
    #[serde(default)]
    pub(super) content_digest: Option<[u8; 32]>,
    pub(super) landed_at: u64,
    pub(super) updated_at: u64,
}

/// The key of the provider message `provider_id` of `source`.
pub(super) fn occurrence_key(source: EntityId, provider_id: &str) -> (EntityId, [u8; 32]) {
    (source, *blake3::hash(provider_id.as_bytes()).as_bytes())
}

/// The key a thread's epoch is kept under.
pub(super) fn thread_hash(thread_key: &str) -> [u8; 32] {
    *blake3::hash(thread_key.as_bytes()).as_bytes()
}

/// The body queue key of a message received at `received_at`.
pub(super) fn body_queue_key(
    source: EntityId,
    received_at: u64,
    provider_id: &str,
) -> (EntityId, u64, [u8; 32]) {
    (
        source,
        u64::MAX - received_at,
        *blake3::hash(provider_id.as_bytes()).as_bytes(),
    )
}

/// The headers of one message a reply to it needs, as its provider gave
/// them, never cut to a label's length: a reply carries them exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct MailReplyHeaders {
    /// The provider's thread id (Gmail `threadId`).
    pub(super) thread_id: Option<String>,
    pub(super) rfc_message_id: Option<String>,
    pub(super) references: Vec<String>,
    pub(super) from: Option<String>,
    pub(super) reply_to: Vec<String>,
    pub(super) subject: Option<String>,
    /// Whether this mailbox sent it: a reply answers someone else's.
    pub(super) sent_by_mailbox: bool,
}

impl MailReplyHeaders {
    pub(super) fn of(headers: &super::wire::MailHeaders) -> Self {
        Self {
            thread_id: headers.thread_id.clone(),
            rfc_message_id: headers.rfc_message_id.clone(),
            references: headers.references.clone(),
            from: headers.from.clone(),
            reply_to: headers.reply_to.clone(),
            subject: headers.subject.clone(),
            sent_by_mailbox: headers.sent_by_mailbox,
        }
    }
}

impl MailOccurrence {
    /// Forgets what the message said: its sender, subject, labels, thread
    /// key, ids and content hashes go, and only the provider id stays, as a
    /// fence a later listing does not land again. The digest of its whole
    /// message stays with the provider id: it proves a copy found later to
    /// be the message forgotten, so the fence holds when the message moves.
    pub(super) fn scrub(&mut self, at: u64) {
        self.presence = MailPresence::Forgotten { at };
        self.thread_key.clear();
        self.content_hashes.clear();
        self.labels.clear();
        self.rfc_message_id = None;
        self.from = None;
        self.subject = None;
        self.attachments.clear();
        self.reply = None;
        self.updated_at = at;
    }
}

/// Records that `rows` landed for the provider message keyed `key`, so an
/// erase of any of them reaches it.
pub(super) fn record_occurrence_rows_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &(EntityId, [u8; 32]),
    rows: &[EntityId],
    at: u64,
) -> Result<()> {
    for row in rows {
        OCCURRENCE_ROWS.put(&vault.store, txn, &(*row, key.0, key.1), &at)?;
    }
    Ok(())
}

/// Owes each of `headers`, the header-only revisions of the provider
/// message keyed `key` its body superseded, a delete, and takes them out of
/// the message's erase reach, so that delete leaves the message as it
/// stands (FIX 15413).
pub(super) fn owe_header_retirements_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &(EntityId, [u8; 32]),
    headers: &[EntityId],
    at: u64,
) -> Result<()> {
    for header in headers {
        OCCURRENCE_ROWS.delete(&vault.store, txn, &(*header, key.0, key.1))?;
        HEADER_RETIREMENTS.put(&vault.store, txn, &(key.0, key.1, *header), &at)?;
    }
    Ok(())
}

/// The entity eraser (deletion/derived_rows.rs): an erased CONVERSATION,
/// TURN or MESSAGE of an imported message scrubs that message's occurrence,
/// so the inbox, the thread and the compliance search no longer list its
/// sender or subject, and its body leaves the queue. A no-op for any other
/// entity.
pub(crate) fn erase_occurrence_rows_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let keys = OCCURRENCE_ROWS.scan_keys(store, txn, id.as_bytes())?;
    if keys.is_empty() {
        return Ok(());
    }
    let at = crate::unix_seconds_now();
    for (row, source, hash) in keys {
        OCCURRENCE_ROWS.delete(store, txn, &(row, source, hash))?;
        let key = (source, hash);
        let Some(mut occurrence) = OCCURRENCES.get(store, txn, &key)? else {
            continue;
        };
        if !matches!(occurrence.presence, MailPresence::Forgotten { .. }) {
            BODY_QUEUE.delete(
                store,
                txn,
                &body_queue_key(source, occurrence.received_at, &occurrence.provider_id),
            )?;
        }
        occurrence.scrub(at);
        OCCURRENCES.put(store, txn, &key, &occurrence)?;
        super::attachments::forget_message_attachments_in_txn(
            store,
            txn,
            source,
            &occurrence.provider_id,
        )?;
    }
    Ok(())
}

/// The provider ids of up to `limit` messages waiting for their bodies,
/// newest first.
pub(super) fn bodies_waiting_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: EntityId,
    limit: usize,
) -> Result<Vec<String>> {
    let mut waiting = Vec::new();
    for row in BODY_QUEUE.iter_from(&vault.store, txn, source.as_bytes())? {
        if waiting.len() >= limit {
            break;
        }
        waiting.push(row?.1);
    }
    Ok(waiting)
}

/// One source's import, as its readers see it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailSyncStatusView {
    pub source_ref: String,
    /// Whether the change feed has an anchor: new mail arrives live.
    pub live: bool,
    /// Whether the newest-first copy reached the oldest message it keeps.
    pub copy_done: bool,
    pub landed: u64,
    pub bodies: u64,
    /// Messages waiting for their bodies.
    pub bodies_waiting: u64,
    pub deleted_at_provider: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_step_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// The status view of `source` in `txn`.
pub(super) fn status_view_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: EntityId,
) -> Result<MailSyncStatusView> {
    let state = SYNC.get(&vault.store, txn, &source)?.unwrap_or_default();
    let bodies_waiting = BODY_QUEUE
        .scan_keys(&vault.store, txn, source.as_bytes())?
        .len() as u64;
    Ok(MailSyncStatusView {
        source_ref: source.to_hex(),
        live: state.anchor.is_some(),
        copy_done: state.backfill_done,
        landed: state.landed,
        bodies: state.bodies,
        bodies_waiting,
        deleted_at_provider: state.deleted_at_provider,
        last_step_at: state.last_step_at,
        last_error: state.last_error,
    })
}
