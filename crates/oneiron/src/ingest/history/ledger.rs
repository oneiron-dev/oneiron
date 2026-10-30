//! The history import ledger: one row per imported source message, keyed by the
//! source and the message's native id and bound to the hash of what was
//! imported. A row commits in the transaction that lands its message, so a
//! message is in the vault exactly when its row is.
//!
//! The key is the native id alone, not the conversation and the id: Claude
//! Code copies a resumed session's lines (same uuid, same time) into the new
//! session's log, and Codex copies a parent thread's items (same id, new time)
//! into a forked or spawned thread's rollout. Keyed per conversation, every
//! copy would land again.
//!
//! Erasing an imported MESSAGE takes its text's hash out of every row that
//! holds it ([`erase_message_in_txn`]). The row keeps the MESSAGE's id in its
//! place, an id the vault's erasure record names too, so a later copy of the
//! same words is not landed again; the texts still in the vault keep theirs.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::{HistoryMessage, HistoryRole, HistorySource, UNKNOWN_SPEAKER};
use crate::entity_id::{EntityId, derived_domains};
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_MESSAGE;
use crate::side_table::{self, Named, SideTable, SideTableDbs};
use crate::store::Store;

const LEDGER: SideTable<String, LedgerRow, Named> =
    SideTable::new(&side_table::INGEST_HISTORY_LEDGER);

/// Longest native id kept in a key as is; a longer one keys by its hash.
const MAX_KEYED_NATIVE_ID: usize = 256;

/// What the ledger knows of one imported message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct LedgerRow {
    /// The native id of the conversation the message landed in.
    pub(super) conversation: String,
    /// The MESSAGE the latest text still in the vault landed as; the last
    /// erased one when none is.
    pub(super) message: EntityId,
    pub(super) turn: EntityId,
    /// [`content_hash`] of every text of the message landed so far and still
    /// in the vault, oldest first. A copy that carries an older text again is
    /// not a new revision.
    pub(super) hashes: Vec<String>,
    /// The MESSAGE each of `hashes` landed as, in the same order.
    pub(super) messages: Vec<EntityId>,
    /// The MESSAGEs of texts erased since they landed: ids the vault's
    /// erasure record names too, never a hash of their words. A copy whose
    /// text derives one of them is not landed again.
    pub(super) erased: Vec<EntityId>,
    /// The native id a later import landed this message under, knowing it by
    /// this row's id as its alias: that row carries this row's texts, so an
    /// erasure follows it there.
    pub(super) successor: Option<String>,
}

impl LedgerRow {
    /// Whether this text of the message has landed ([`holds`]).
    pub(super) fn holds(&self, message: &HistoryMessage) -> bool {
        holds(&self.hashes, message)
    }

    /// Whether this text of the message landed and was erased since: under
    /// the message's id or its alias, its words derive one of the row's
    /// erased MESSAGEs. Words of an unknown speaker are matched by the same
    /// words with the speaker known too, as [`holds`] matches them.
    pub(super) fn held_erased(
        &self,
        source: HistorySource,
        message: &HistoryMessage,
    ) -> Result<bool> {
        if self.erased.is_empty() {
            return Ok(false);
        }
        let mut texts = vec![hash(message, false)];
        if message.said_by == Some(UNKNOWN_SPEAKER) {
            texts.push(hash(message, true));
        }
        for native_id in std::iter::once(&message.native_id).chain(&message.alias) {
            for text in &texts {
                let id = super::land::derive(
                    derived_domains::HISTORY_MESSAGE,
                    &[source.source_id(), native_id, text],
                )?;
                if self.erased.contains(&id) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// The revision the next changed text lands as (the first import is 0),
    /// counting erased texts too.
    pub(super) fn next_revision(&self) -> u16 {
        u16::try_from(self.hashes.len() + self.erased.len()).unwrap_or(u16::MAX)
    }

    /// Takes the text `message` landed as out of the row and keeps its id
    /// among the erased. `false` when the row holds no such text.
    fn erase(&mut self, message: EntityId) -> bool {
        let Some(at) = self.messages.iter().position(|landed| *landed == message) else {
            return false;
        };
        self.messages.remove(at);
        if at < self.hashes.len() {
            self.hashes.remove(at);
        }
        if !self.erased.contains(&message) {
            self.erased.push(message);
        }
        if self.message == message
            && let Some(latest) = self.messages.last()
        {
            self.message = *latest;
        }
        true
    }
}

fn key(source: HistorySource, native_id: &str) -> String {
    if native_id.len() <= MAX_KEYED_NATIVE_ID {
        format!("{}:{native_id}", source.source_id())
    } else {
        let digest = blake3::hash(native_id.as_bytes());
        format!("{}:#{}", source.source_id(), digest.to_hex())
    }
}

/// What a re-import compares: the speaker's side and the words, and whether
/// the source left the speaker unknown ([`UNKNOWN_SPEAKER`]). Words of an
/// unknown speaker hash apart from the same words with the speaker known.
pub(super) fn content_hash(message: &HistoryMessage) -> String {
    hash(message, message.said_by == Some(UNKNOWN_SPEAKER))
}

/// Whether `landed`, the [`content_hash`]es of what landed of one message,
/// holds `message`. Words of an unknown speaker are held by the same words
/// with the speaker known too, so a later copy never lands them as unknown
/// again; words with the speaker known are not held by the same words of an
/// unknown speaker, so the import that knows who said them lands them, as a
/// revision the Dreamer reads.
pub(super) fn holds(landed: &[String], message: &HistoryMessage) -> bool {
    let held = |unknown| landed.contains(&hash(message, unknown));
    held(false) || (message.said_by == Some(UNKNOWN_SPEAKER) && held(true))
}

fn hash(message: &HistoryMessage, unknown_speaker: bool) -> String {
    let mut hasher = blake3::Hasher::new();
    if unknown_speaker {
        hasher.update(b"unknown\0");
    }
    hasher.update(match message.role {
        HistoryRole::User => b"user\0",
        HistoryRole::Assistant => b"asst\0",
    });
    hasher.update(message.text.as_bytes());
    hasher.finalize().to_hex().to_string()
}

pub(super) fn get(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    source: HistorySource,
    native_id: &str,
) -> Result<Option<LedgerRow>> {
    LEDGER.get(dbs, txn, &key(source, native_id))
}

/// The row of `message`: under its native id, or else under the alias an
/// earlier import may have landed it by.
pub(super) fn find(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    source: HistorySource,
    message: &HistoryMessage,
) -> Result<Option<LedgerRow>> {
    if let Some(row) = get(dbs, txn, source, &message.native_id)? {
        return Ok(Some(row));
    }
    match &message.alias {
        Some(alias) => get(dbs, txn, source, alias),
        None => Ok(None),
    }
}

pub(super) fn put(
    dbs: &impl SideTableDbs,
    txn: &mut heed::RwTxn<'_>,
    source: HistorySource,
    native_id: &str,
    row: &LedgerRow,
) -> Result<()> {
    LEDGER.put(dbs, txn, &key(source, native_id), row)
}

/// How many messages of `source` the ledger holds.
pub(super) fn count(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    source: HistorySource,
) -> Result<usize> {
    let prefix = format!("{}:", source.source_id());
    Ok(LEDGER.scan_keys(dbs, txn, prefix.as_bytes())?.len())
}

/// When `previous`, the row `message` revises, is the row its alias keys,
/// names `message`'s own id as that row's successor: the row about to land
/// under that id carries its texts, and an erasure follows it there.
pub(super) fn mark_successor(
    dbs: &impl SideTableDbs,
    txn: &mut heed::RwTxn<'_>,
    source: HistorySource,
    message: &HistoryMessage,
    previous: Option<&LedgerRow>,
) -> Result<()> {
    let (Some(previous), Some(alias)) = (previous, &message.alias) else {
        return Ok(());
    };
    if get(dbs, txn, source, &message.native_id)?.is_some() {
        return Ok(());
    }
    let mut row = previous.clone();
    row.successor = Some(message.native_id.clone());
    put(dbs, txn, source, alias, &row)
}

/// Takes an erased imported MESSAGE's text out of the ledger (FIX 9876): its
/// hash leaves the row of the native id its provenance names and each row
/// that row's successors carry it in, and each keeps the MESSAGE's id among
/// its erased. Texts still in the vault keep their hashes. A no-op for any
/// other record. Runs in the erase transaction, before the body goes.
pub(crate) fn erase_message_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let Some(raw) = store.port_entity_record(wtxn, id)? else {
        return Ok(());
    };
    if raw.entity_type != ENTITY_TYPE_MESSAGE {
        return Ok(());
    }
    let Some((source, native_id)) = imported_origin(&raw.body) else {
        return Ok(());
    };
    let mut seen = HashSet::new();
    let mut next = Some(native_id);
    while let Some(native_id) = next.take() {
        if !seen.insert(native_id.clone()) {
            break;
        }
        let Some(mut row) = get(store, wtxn, source, &native_id)? else {
            break;
        };
        next = row.successor.clone();
        if row.erase(*id) {
            put(store, wtxn, source, &native_id, &row)?;
        }
    }
    Ok(())
}

/// The source and the native id an imported MESSAGE's provenance names
/// (`import.source` and `import.id` in its metadata).
fn imported_origin(body: &[u8]) -> Option<(HistorySource, String)> {
    let field = |value: &rmpv::Value, name: &str| match value {
        rmpv::Value::Map(entries) => entries
            .iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .map(|(_, value)| value.clone()),
        _ => None,
    };
    let message = rmpv::decode::read_value(&mut &body[..]).ok()?;
    let import = field(&field(&message, "metadata")?, "import")?;
    let source = HistorySource::parse(field(&import, "source")?.as_str()?)?;
    let native_id = field(&import, "id")?.as_str()?.to_owned();
    Some((source, native_id))
}
