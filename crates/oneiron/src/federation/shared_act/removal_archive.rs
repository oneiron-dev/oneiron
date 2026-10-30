//! An export-first removal's archive as it is kept (FIX-LIST 8224): the
//! delivered copy, and beside it the position each archived record stood at
//! when the removal froze it. The positions never leave the vault; they let
//! a holder the removed Owner transferred the archive slip to take only what
//! that holder's own bounds admit, projected from the frozen archive itself
//! (`REMOVAL_ARCHIVE_TRANSFER_MODE`). The removed Owner proving the mint's
//! own key keeps the copy exactly as stored: the positions are kept as their
//! own encoded bytes, so that read never decodes them. A projection whose own
//! input does not read (the positions, the archive's manifest, members or
//! rows) answers the stored copy as it did before projection existed
//! (`ISOLATION_NEW_CHECK_ERROR_MODE`); bounds that were judged still bound.
//! A one-shot transfer is served once (FIX-LIST 10773): the row keeps each
//! slip an archive door spent so, on every archive of its removed Owner.

use std::collections::BTreeSet;

use super::{REMOVAL_EXPORT, RemovalExportCopy, removal_export_key};
use crate::authority::{ISOLATION_NEW_CHECK_ERROR_MODE, NewCheckErrorMode};
use crate::error::{Error, Result};
use crate::federation::Scope;
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

/// A removal archive's row: the delivered copy, and its frozen positions as
/// their own encoded bytes ([`freeze_positions_in_txn`]).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredRemovalExport {
    pub(crate) copy: RemovalExportCopy,
    positions: Vec<u8>,
    /// The one-shot transferred slips an archive door already served, by
    /// slip id (FIX-LIST 10773): each is kept on every archive of the
    /// removed Owner, so it takes none of them again.
    spent_slips: BTreeSet<[u8; 32]>,
}

impl StoredRemovalExport {
    pub(super) fn new(copy: RemovalExportCopy, positions: Vec<u8>) -> Self {
        Self {
            copy,
            positions,
            spent_slips: BTreeSet::new(),
        }
    }

    /// The copy `admits` leaves its holder, judged record by record on the
    /// frozen positions: the stored copy when it admits every record, none
    /// when it admits none, else the stored archive projected onto those it
    /// admits. Positions or an archive that do not read leave the stored
    /// copy ([`keep_stored_copy`]).
    fn projected(
        self,
        admits: &dyn Fn(EntityId, Option<&Scope>) -> bool,
    ) -> Option<RemovalExportCopy> {
        let positions: Vec<FrozenPosition> = match rmp_serde::from_slice(&self.positions) {
            Ok(positions) => positions,
            Err(_) => return Some(keep_stored_copy(self.copy, "frozen positions")),
        };
        let archived: BTreeSet<EntityId> = positions.iter().map(|record| record.id).collect();
        let kept: BTreeSet<EntityId> = positions
            .iter()
            .filter(|record| admits(record.id, record.scope.as_ref()))
            .map(|record| record.id)
            .collect();
        if kept.is_empty() {
            return None;
        }
        if kept.len() == archived.len() {
            return Some(self.copy);
        }
        let TransferMode::ProjectStoredSnapshot = REMOVAL_ARCHIVE_TRANSFER_MODE;
        let mut copy = self.copy;
        let Ok(bytes) =
            crate::batch::export::project_stored_archive(&copy.export.archive, &archived, &kept)
        else {
            return Some(keep_stored_copy(copy, "stored archive"));
        };
        let ProjectedDigest::ProjectedBytes = REMOVAL_ARCHIVE_PROJECTED_DIGEST;
        copy.export.digest = blake3::hash(&bytes).to_hex().to_string();
        copy.export.archive = bytes;
        Some(copy)
    }
}

/// [`ISOLATION_NEW_CHECK_ERROR_MODE`] for a projection whose `input` did not
/// read: the stored copy, as every holder took it before projection
/// existed. The warning names the removal receipt and the input only.
fn keep_stored_copy(copy: RemovalExportCopy, input: &'static str) -> RemovalExportCopy {
    match ISOLATION_NEW_CHECK_ERROR_MODE {
        NewCheckErrorMode::KeepExistingPath => {
            tracing::warn!(
                receipt = %copy.receipt_id,
                input,
                policy = ?ISOLATION_NEW_CHECK_ERROR_MODE,
                "a transferred removal archive did not project; its holder takes the stored copy \
                 (FIX-LIST 8224)"
            );
            copy
        }
    }
}

/// Each of `ids`'s position as `txn`, the archive's own snapshot, holds it
/// ([`Vault::export_positions_in_txn`]), encoded on their own.
pub(super) fn freeze_positions_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    ids: &BTreeSet<EntityId>,
) -> Result<Vec<u8>> {
    let positions: Vec<FrozenPosition> = vault
        .export_positions_in_txn(txn, ids)?
        .into_iter()
        .map(|(id, scope)| FrozenPosition { id, scope })
        .collect();
    rmp_serde::to_vec_named(&positions)
        .map_err(|_| Error::InvariantViolation("removal archive positions do not encode"))
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
                && let Some(copy) = stored.projected(admits)
            {
                copies.push(copy);
            }
        }
        Ok(copies)
    }

    /// Whether an archive door already served the one-shot transferred slip
    /// `slip_id`: any of `member`'s archives keeps its spend (FIX-LIST
    /// 10773).
    pub(crate) fn removal_archive_slip_spent_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        member: EntityId,
        slip_id: &[u8; 32],
    ) -> Result<bool> {
        let prefix = removal_export_key(&member.to_hex(), "");
        Ok(REMOVAL_EXPORT
            .scan_from(&self.store, txn, prefix.as_bytes())?
            .iter()
            .any(|(_, stored)| stored.spent_slips.contains(slip_id)))
    }

    /// Spends the one-shot transferred slip `slip_id` on every archive of
    /// `member`, in the writer whose answer served it (FIX-LIST 10773).
    pub(crate) fn spend_removal_archive_slip_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        member: EntityId,
        slip_id: [u8; 32],
    ) -> Result<()> {
        let prefix = removal_export_key(&member.to_hex(), "");
        for (row_key, mut stored) in
            REMOVAL_EXPORT.scan_from(&self.store, txn, prefix.as_bytes())?
        {
            if stored.spent_slips.insert(slip_id) {
                REMOVAL_EXPORT.put(&self.store, txn, &row_key, &stored)?;
            }
        }
        Ok(())
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
            Some(stored) if now < stored.copy.expires_at => Ok(stored.projected(admits)),
            _ => Ok(None),
        }
    }
}
