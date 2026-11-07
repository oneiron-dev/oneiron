//! What the importer keeps per source and per provider message: where its
//! listing and its change feed stand, and each message's rows, stage and
//! presence at the provider. The four ids stay apart (MAIL-GOOGLE = A): the
//! Oneiron rows, the provider's id (the key here), the RFC `Message-ID`
//! with the content hash, and the provider's thread id.

use serde::{Deserialize, Serialize};

use super::source::MailCopySetting;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

/// One source's sync state, by the source.
pub const SYNC: SideTable<EntityId, MailSyncState, Named> =
    SideTable::new(&side_table::MAIL_PACK_SYNC);
/// One provider message of one source, by the source and the BLAKE3 of the
/// provider's message id.
pub const OCCURRENCES: SideTable<(EntityId, [u8; 32]), MailOccurrence, Named> =
    SideTable::new(&side_table::MAIL_PACK_OCCURRENCE);
/// The messages that landed with their headers only and wait for their
/// bodies, newest first: by the source, `u64::MAX` less the receive time,
/// and the BLAKE3 of the provider's id. The value is the provider's id.
pub const BODY_QUEUE: SideTable<(EntityId, u64, [u8; 32]), String, Named> =
    SideTable::new(&side_table::MAIL_PACK_BODY_QUEUE);
/// The rows each provider message landed as, so an erase of any of them
/// reaches the message: by the row (its CONVERSATION, TURN or a MESSAGE
/// revision), the source and the BLAKE3 of the provider's id. The value is
/// when it was recorded.
pub const OCCURRENCE_ROWS: SideTable<(EntityId, EntityId, [u8; 32]), u64, Named> =
    SideTable::new(&side_table::MAIL_PACK_OCCURRENCE_ROW);

/// Where one source's import stands.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MailSyncState {
    /// The provider's change anchor the source stands at (Gmail
    /// `historyId`); changes after it are read from the change feed.
    pub anchor: Option<String>,
    /// The newest-first listing's next page; `None` before the first page
    /// and once it is done.
    pub backfill_page: Option<String>,
    /// Whether the listing reached the oldest message it copies.
    pub backfill_done: bool,
    /// The cutoff the listing runs under (recent months), so a changed
    /// setting starts it over.
    pub backfill_newer_than: Option<u64>,
    /// The copy setting the listing runs under; a changed setting, or
    /// `None` after an expired anchor, starts it over with a fresh cutoff.
    #[serde(default)]
    pub backfill_copy: Option<MailCopySetting>,
    /// Bumped each time the listing starts over (an expired anchor, a
    /// changed copy setting).
    pub generation: u64,
    /// The change feed's next page, read from `history_page_anchor`: a feed
    /// longer than one step's budget goes on from it at the next step.
    #[serde(default)]
    pub history_page: Option<String>,
    #[serde(default)]
    pub history_page_anchor: Option<String>,
    pub landed: u64,
    pub bodies: u64,
    pub deleted_at_provider: u64,
    pub last_step_at: Option<u64>,
    /// The last step's failure, in words, for the source's owner.
    pub last_error: Option<String>,
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
pub struct MailOccurrence {
    pub provider_id: String,
    pub thread_key: String,
    pub conversation: EntityId,
    pub turn: EntityId,
    /// Each revision's MESSAGE, oldest first: the headers, then the whole
    /// message.
    pub messages: Vec<EntityId>,
    /// Each revision's content hash, in the same order.
    pub content_hashes: Vec<String>,
    pub stage: MailStage,
    pub presence: MailPresence,
    pub labels: Vec<String>,
    pub rfc_message_id: Option<String>,
    /// The sender and subject, as the inbox lists the message.
    pub from: Option<String>,
    pub subject: Option<String>,
    pub received_at: u64,
    /// Whether a search fetched it: kept whatever the copy setting.
    pub searched: bool,
    pub landed_at: u64,
    pub updated_at: u64,
}

/// The body queue key of a message received at `received_at`.
pub fn body_queue_key(
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

impl MailOccurrence {
    /// Forgets what the message said: its sender, subject, labels, thread
    /// key, ids and content hashes go, and only the provider id stays, as a
    /// fence a later listing does not land again.
    pub fn scrub(&mut self, at: u64) {
        self.presence = MailPresence::Forgotten { at };
        self.thread_key.clear();
        self.content_hashes.clear();
        self.labels.clear();
        self.rfc_message_id = None;
        self.from = None;
        self.subject = None;
        self.updated_at = at;
    }
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
    }
    Ok(())
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
