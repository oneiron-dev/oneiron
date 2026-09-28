//! Owner-only archive impact preview and confirmed ARCH-0038 erasure.

use crate::EntityId;
use crate::memory::support::verify_deletion_authority_in_txn;
use crate::memory::{DeleteReceipt, Memory, MemoryError, MemoryResult, SafeDeleteReason};
use crate::side_table::{self, HexId, Raw, SideTable};

/// The ARCH-0023b cleanup-archive marker (owned by `crate::deletion::tombstone`);
/// read-only here for the purge preview. Other modules keep using
/// `crate::deletion::archive_tombstone_key` plus their own raw `sync_state`
/// access, per that module's own doc comment.
const ARCHIVE_MARKER: SideTable<HexId, Vec<u8>, Raw> =
    SideTable::new(&side_table::DELETION_ARCHIVE_MARKER);

/// One archived entity's retained record bytes. Secondary indexes and historical
/// carriers are handled by ARCH-0038; this is not a filesystem-space estimate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivePurgeEntry {
    pub entity: EntityId,
    pub record_bytes: u64,
    fingerprint: [u8; 32],
    archive_marker: Vec<u8>,
}

/// A snapshot-bound confirmation. Fields are read-only so callers cannot add a
/// target they did not preview. Restores and changed records invalidate it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivePurgePreview {
    entries: Vec<ArchivePurgeEntry>,
}

impl ArchivePurgePreview {
    pub fn entries(&self) -> &[ArchivePurgeEntry] {
        &self.entries
    }
    pub fn record_bytes(&self) -> u64 {
        self.entries.iter().map(|row| row.record_bytes).sum()
    }
}

impl Memory<'_> {
    /// Preview only explicit archive targets, under the same owner authority as
    /// erasure. No cron path holds a Memory owner capability.
    pub fn preview_archive_purge(&self, ids: &[EntityId]) -> MemoryResult<ArchivePurgePreview> {
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        verify_deletion_authority_in_txn(self.vault, &txn, self.actor, self.actor_class)?;
        let mut entries = Vec::new();
        // One preview/receipt per id, with stable order regardless of input.
        let mut targets = ids.to_vec();
        targets.sort_unstable();
        targets.dedup();
        for id in targets {
            let marker = archive_marker(self.vault, &txn, id)?;
            let raw = self
                .vault
                .get_raw_in(&txn, &id)?
                .ok_or_else(|| MemoryError::from(crate::Error::EntityNotFound))?;
            entries.push(ArchivePurgeEntry {
                entity: id,
                record_bytes: raw.len() as u64,
                fingerprint: *blake3::hash(&raw).as_bytes(),
                archive_marker: marker,
            });
        }
        Ok(ArchivePurgePreview { entries })
    }

    /// Each result carries its own ARCH-0038 receipt or refusal. A later row's
    /// failure must not hide an earlier completed erasure. The deletion rail
    /// rechecks both authority and the preview inside its linearizing transaction.
    pub fn confirm_archive_purge(
        &self,
        preview: &ArchivePurgePreview,
    ) -> Vec<(EntityId, MemoryResult<DeleteReceipt>)> {
        preview
            .entries
            .iter()
            .map(|row| {
                let result = self.safe_delete_checked(
                    &row.entity.to_hex(),
                    SafeDeleteReason::UserHardDelete,
                    |txn| {
                        let marker = archive_marker(self.vault, txn, row.entity)?;
                        let raw = self
                            .vault
                            .get_raw_in(txn, &row.entity)?
                            .ok_or_else(stale_preview)?;
                        if marker != row.archive_marker
                            || blake3::hash(&raw).as_bytes() != &row.fingerprint
                        {
                            return Err(stale_preview());
                        }
                        Ok(())
                    },
                );
                (row.entity, result)
            })
            .collect()
    }
}

fn stale_preview() -> MemoryError {
    MemoryError::bad_request("archive preview no longer matches; preview again")
}

fn archive_marker(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> MemoryResult<Vec<u8>> {
    if vault
        .archive_tombstone_in_txn(txn, &id)?
        .is_none_or(|marker| {
            marker.reason != Some(crate::deletion::TombstoneReason::ArchivedByCleanup)
        })
    {
        return Err(stale_preview());
    }
    ARCHIVE_MARKER
        .get(&vault.store, txn, &HexId(id))?
        .ok_or_else(stale_preview)
}
