//! Whether an archived NOTE was read since its archive (OF-073, FIX 2419;
//! CALLS "FIX 2419 NOTE read since archiving"). Every ordinary read door
//! refuses an archived NOTE: a NOTE read, a scoped point read, search, a
//! context pack, graph-fs, the board and the SDK all read an archive as
//! deleted (`port_deletion_state`). A door that still serves an archived
//! NOTE's words stamps the archive here as read, and the tombstone review
//! never proposes a NOTE read in its current archive. Device replication,
//! a backup and a replay of a page read before the archive are not reads.

use serde::{Deserialize, Serialize};

use crate::deletion::TombstoneReason;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

const READ: SideTable<EntityId, ArchiveRead, Named> =
    SideTable::new(&side_table::NOTE_ARCHIVE_READ);

/// The archive a NOTE was read in, and when.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct ArchiveRead {
    /// Unix seconds the NOTE was archived, and that archive's request id.
    archived_at: u64,
    archive_request: Option<[u8; 16]>,
    /// Unix seconds of the first read in that archive.
    read_at: u64,
}

/// Whether `note` was read in the archive of `archived_at` and
/// `archive_request`.
pub(super) fn read_since_archive_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
    archived_at: u64,
    archive_request: Option<[u8; 16]>,
) -> Result<bool> {
    Ok(READ.get(store, txn, &note)?.is_some_and(|read| {
        read.archived_at == archived_at && read.archive_request == archive_request
    }))
}

/// Stamps each archived NOTE of `notes` as read in its current archive; a
/// live NOTE, or one already stamped in this archive, is left alone.
pub(super) fn witness_archived_reads(
    vault: &Vault,
    notes: impl IntoIterator<Item = EntityId>,
) -> Result<()> {
    let notes: Vec<EntityId> = notes.into_iter().collect();
    let unread = {
        let txn = vault.store.env.read_txn()?;
        let mut unread = Vec::new();
        for note in notes {
            if let Some(marker) = vault.archive_tombstone_in_txn(&txn, &note)?
                && marker.reason == Some(TombstoneReason::ArchivedByCleanup)
                && !read_since_archive_in_txn(
                    &vault.store,
                    &txn,
                    note,
                    marker.deleted_at,
                    marker.request_id,
                )?
            {
                unread.push(note);
            }
        }
        unread
    };
    if unread.is_empty() {
        return Ok(());
    }
    vault.with_write_txn(|txn| {
        let now = vault.now_recorded_at();
        for note in &unread {
            let Some(marker) = vault.archive_tombstone_in_txn(txn, note)? else {
                continue;
            };
            if marker.reason != Some(TombstoneReason::ArchivedByCleanup)
                || read_since_archive_in_txn(
                    &vault.store,
                    txn,
                    *note,
                    marker.deleted_at,
                    marker.request_id,
                )?
            {
                continue;
            }
            let read = ArchiveRead {
                archived_at: marker.deleted_at,
                archive_request: marker.request_id,
                read_at: now,
            };
            READ.put(&vault.store, txn, note, &read)?;
        }
        Ok(())
    })
}
