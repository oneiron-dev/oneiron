//! What the importer keeps per source and per provider message: where its
//! listing and its change feed stand, and each message's rows, stage and
//! presence at the provider. The four ids stay apart (MAIL-GOOGLE = A): the
//! Oneiron rows, the provider's id (the key here), the RFC `Message-ID`
//! with the content hash, and the provider's thread id.

use serde::{Deserialize, Serialize};

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
    /// Bumped each time the listing starts over (an expired anchor, a
    /// changed copy setting).
    pub(super) generation: u64,
    pub(super) landed: u64,
    pub(super) bodies: u64,
    pub(super) deleted_at_provider: u64,
    pub(super) last_step_at: Option<u64>,
    /// The last step's failure, in words, for the source's owner.
    pub(super) last_error: Option<String>,
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
    pub(super) landed_at: u64,
    pub(super) updated_at: u64,
}

/// The key of the provider message `provider_id` of `source`.
pub(super) fn occurrence_key(source: EntityId, provider_id: &str) -> (EntityId, [u8; 32]) {
    (source, *blake3::hash(provider_id.as_bytes()).as_bytes())
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
