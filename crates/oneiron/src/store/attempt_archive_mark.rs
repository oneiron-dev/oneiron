//! Core half of `store::attempt_archive_mark`: its store-layer items live in `oneiron_store::attempt_archive_mark` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::attempt_archive_mark::*;

use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::store::attempt_id::AttemptId;

/// The mark table. Key: id16, an attempt's id or a kept record's entity id.
pub(crate) const MARK: SideTable<[u8; 16], Vec<u8>, Raw> =
    SideTable::new(&side_table::VAULT_CLEANUP_ATTEMPT_ARCHIVE);

/// The mark row for `id` as stored, whatever it reads as.
pub(crate) fn raw_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &[u8; 16],
) -> Result<Option<Vec<u8>>> {
    MARK.get(store, txn, id)
}

pub(crate) fn put_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &[u8; 16],
    mark: CleanupMark,
) -> Result<()> {
    MARK.put(store, txn, id, &mark.encode())
}

pub(crate) fn delete_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>, id: &[u8; 16]) -> Result<()> {
    MARK.delete(store, txn, id)?;
    Ok(())
}

/// Moves an attempt's cleanup mark to the bytes its row was rewritten to in
/// this transaction, when the mark bound the row as it stood (`before`): an
/// erase that rewrites a row in place leaves it archived by the same run
/// (FIX 7076), or kept by the owner. A stale or unreadable mark bound bytes
/// the row no longer holds, so it is removed, never rebound: no hash of
/// those bytes outlives the erase (FIX 7615). An absent mark stays absent.
pub(crate) fn refresh_archived_attempt_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: AttemptId,
    before: &[u8],
    after: &[u8],
) -> Result<()> {
    let bound = revision_of(before);
    let revision = revision_of(after);
    let Some(raw) = raw_in_txn(store, txn, id.as_bytes())? else {
        return Ok(());
    };
    match CleanupMark::decode(&raw).and_then(|mark| mark.moved(&bound, &revision)) {
        Some(moved) => put_in_txn(store, txn, id.as_bytes(), moved),
        None => delete_in_txn(store, txn, id.as_bytes()),
    }
}
