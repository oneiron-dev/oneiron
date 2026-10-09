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

use serde::{Deserialize, Serialize};

use super::{HistoryMessage, HistoryRole, HistorySource};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable, SideTableDbs};

const LEDGER: SideTable<String, LedgerRow, Named> =
    SideTable::new(&side_table::INGEST_HISTORY_LEDGER);

/// Longest native id kept in a key as is; a longer one keys by its hash.
const MAX_KEYED_NATIVE_ID: usize = 256;

/// What the ledger knows of one imported message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct LedgerRow {
    /// The native id of the conversation the message landed in.
    pub(super) conversation: String,
    pub(super) message: EntityId,
    pub(super) turn: EntityId,
    /// [`content_hash`] of every text of the message landed so far, oldest
    /// first. A copy that carries an older text again is not a new revision.
    pub(super) hashes: Vec<String>,
}

impl LedgerRow {
    /// Whether this text of the message has landed.
    pub(super) fn holds(&self, hash: &str) -> bool {
        self.hashes.iter().any(|landed| landed == hash)
    }

    /// The revision the next changed text lands as (the first import is 0).
    pub(super) fn next_revision(&self) -> u16 {
        u16::try_from(self.hashes.len()).unwrap_or(u16::MAX)
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

/// What a re-import compares: the speaker's side and the words.
pub(super) fn content_hash(message: &HistoryMessage) -> String {
    let mut hasher = blake3::Hasher::new();
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
