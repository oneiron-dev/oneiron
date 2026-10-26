//! An export-first removal's archive as it is kept (FIX-LIST 8224): the
//! delivered copy, and beside it the position each archived record stood at
//! when the removal froze it. The positions never leave the vault; they let
//! a holder the removed Owner transferred the archive slip to take only what
//! that holder's own bounds admit, projected from the frozen archive itself
//! (`REMOVAL_ARCHIVE_TRANSFER_MODE`). The removed Owner proving the mint's
//! own key keeps the copy exactly as stored.

use std::collections::BTreeSet;

use super::{REMOVAL_EXPORT, RemovalExportCopy, removal_export_key};
use crate::error::Result;
use crate::federation::Scope;
use crate::federation::record_scope::ScopedRecord;
use crate::{EntityId, Vault};

/// How a transferred holder takes a removal archive (CALLS
/// "REMOVAL_ARCHIVE_TRANSFER_MODE", accepted by the Engine 10-22 05:3x).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransferMode {
    /// The stored archive, cut down to the records its bounds admit.
    ProjectStoredSnapshot,
}

const REMOVAL_ARCHIVE_TRANSFER_MODE: TransferMode = TransferMode::ProjectStoredSnapshot;

/// What a projected archive's `digest` names (CALLS
/// "REMOVAL_ARCHIVE_PROJECTED_DIGEST", open): the bytes the holder receives.
/// The removal receipt keeps the stored archive's own digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectedDigest {
    ProjectedBytes,
}

const REMOVAL_ARCHIVE_PROJECTED_DIGEST: ProjectedDigest = ProjectedDigest::ProjectedBytes;

/// One archived record and the position it stood at when the removal froze
/// the archive; `None` where it carried none.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FrozenPosition {
    id: EntityId,
    scope: Option<Scope>,
}

/// A removal archive's row: the delivered copy and its frozen positions.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredRemovalExport {
    pub(crate) copy: RemovalExportCopy,
    positions: Vec<FrozenPosition>,
}

impl StoredRemovalExport {
    pub(super) fn new(copy: RemovalExportCopy, positions: Vec<FrozenPosition>) -> Self {
        Self { copy, positions }
    }

    /// The copy `admits` leaves its holder, judged record by record on the
    /// frozen positions: the stored copy when it admits every record, none
    /// when it admits none, else the stored archive projected onto those it
    /// admits. A projection that fails is an error, never the whole archive.
    fn projected(
        self,
        admits: &dyn Fn(EntityId, Option<&Scope>) -> bool,
    ) -> Result<Option<RemovalExportCopy>> {
        let archived: BTreeSet<EntityId> = self.positions.iter().map(|record| record.id).collect();
        let kept: BTreeSet<EntityId> = self
            .positions
            .iter()
            .filter(|record| admits(record.id, record.scope.as_ref()))
            .map(|record| record.id)
            .collect();
        if kept.is_empty() {
            return Ok(None);
        }
        if kept.len() == archived.len() {
            return Ok(Some(self.copy));
        }
        let TransferMode::ProjectStoredSnapshot = REMOVAL_ARCHIVE_TRANSFER_MODE;
        let mut copy = self.copy;
        let bytes =
            crate::batch::export::project_stored_archive(&copy.export.archive, &archived, &kept)?;
        let ProjectedDigest::ProjectedBytes = REMOVAL_ARCHIVE_PROJECTED_DIGEST;
        copy.export.digest = blake3::hash(&bytes).to_hex().to_string();
        copy.export.archive = bytes;
        Ok(Some(copy))
    }
}

/// Each exported record's position as the export read it.
pub(super) fn freeze_positions(records: &[ScopedRecord]) -> Vec<FrozenPosition> {
    records
        .iter()
        .map(|record| FrozenPosition {
            id: record.id,
            scope: record.scope.clone(),
        })
        .collect()
}

impl Vault {
    /// [`Self::removal_exports_in_txn`] for a holder the removed Owner
    /// transferred the slip to: each archive cut down to the records
    /// `admits` takes, and one it takes none of left out.
    pub(crate) fn projected_removal_exports_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        member: EntityId,
        now: u64,
        admits: &dyn Fn(EntityId, Option<&Scope>) -> bool,
    ) -> Result<Vec<RemovalExportCopy>> {
        let prefix = removal_export_key(&member.to_hex(), "");
        let mut copies = Vec::new();
        for (_, stored) in REMOVAL_EXPORT.scan_from(&self.store, txn, prefix.as_bytes())? {
            if now < stored.copy.expires_at
                && let Some(copy) = stored.projected(admits)?
            {
                copies.push(copy);
            }
        }
        Ok(copies)
    }

    /// [`Self::removal_export_in_txn`] for a transferred holder, as
    /// [`Self::projected_removal_exports_in_txn`] cuts it.
    pub(crate) fn projected_removal_export_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        member: EntityId,
        receipt_id: EntityId,
        now: u64,
        admits: &dyn Fn(EntityId, Option<&Scope>) -> bool,
    ) -> Result<Option<RemovalExportCopy>> {
        let row_key = removal_export_key(&member.to_hex(), &receipt_id.to_hex());
        match REMOVAL_EXPORT.get(&self.store, txn, &row_key)? {
            Some(stored) if now < stored.copy.expires_at => stored.projected(admits),
            _ => Ok(None),
        }
    }
}
