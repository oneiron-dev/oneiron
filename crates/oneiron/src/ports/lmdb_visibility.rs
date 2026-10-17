//! Transaction-local visibility ledger for canonical and composed session views.
use super::{DeletionMarker, DeletionState, TombstoneStoreRead, WindowAddress, WindowDeletionRows};
use crate::side_table::{self, HexId, Raw, SideTable};
use crate::{EntityId, Vault, error::Result, store::ManifestDbs};
use heed::RoTxn;

/// The `sync_state` table of one deletion family; each is keyed by the row id.
fn marker_table(marker: DeletionMarker) -> SideTable<HexId, Vec<u8>, Raw> {
    SideTable::new(match marker {
        DeletionMarker::Archive => &side_table::DELETION_ARCHIVE_MARKER,
        DeletionMarker::HardDelete => &side_table::DELETION_HARD_DELETE_MARKER,
        DeletionMarker::RowFence => &side_table::DELETION_ROW_FENCE,
        DeletionMarker::IdentitySoftDelete => &side_table::DELETION_IDENTITY_SOFT_DELETE_MARKER,
        DeletionMarker::WindowAddress => &side_table::DELETION_WINDOW_LABEL,
    })
}
impl<T: ManifestDbs> TombstoneStoreRead for T {
    fn port_tombstone_records<'a>(
        &self,
        txn: &'a RoTxn<'_>,
        family: super::DeletionFamily,
    ) -> Result<super::PortRows<'a, (EntityId, crate::deletion::DecodedTombstoneValue)>> {
        let prefix = match family {
            super::DeletionFamily::Archive => crate::deletion::ARCHIVE_TOMBSTONE_PREFIX,
            super::DeletionFamily::HardDelete => crate::deletion::LOCAL_HARD_DELETE_PREFIX,
        };
        Ok(Box::new(
            self.sync_state()
                .prefix_iter(txn, prefix)?
                .filter_map(move |row| {
                    let (key, value) = match row {
                        Ok(row) => row,
                        Err(error) => return Some(Err(error)),
                    };
                    let id = key
                        .strip_prefix(prefix)
                        .and_then(|hex| EntityId::from_hex(hex).ok())?;
                    Some(Ok((id, crate::deletion::decode_tombstone_value(&value))))
                }),
        ))
    }

    fn port_deletion_state(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<DeletionState> {
        let archived = self
            .sync_state()
            .get(txn, crate::deletion::archive_tombstone_key(id).as_str())?
            .is_some();
        let stale = super::integrity::stale_in_txn(self, txn, id)?;
        let deleted = archived || removed_in_txn(self, txn, id)?;
        Ok(DeletionState {
            archived,
            deleted,
            stale,
        })
    }

    fn port_deletion_marker(
        &self,
        txn: &RoTxn<'_>,
        marker: DeletionMarker,
        id: &EntityId,
    ) -> Result<Option<Vec<u8>>> {
        marker_table(marker).get_bytes(self, txn, &HexId(*id))
    }

    fn port_deletion_marked(
        &self,
        txn: &RoTxn<'_>,
        marker: DeletionMarker,
        id: &EntityId,
    ) -> Result<bool> {
        marker_table(marker).contains(self, txn, &HexId(*id))
    }
}

/// Whether something other than an archive deletes the row `id`. An archive
/// is a local visibility marker that keeps the row whole; this is the rest of
/// [`DeletionState::deleted`].
pub(crate) fn removed_in_txn(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let raw = dbs.entities().get(txn, id.as_bytes())?;
    // Every answer is an indexed marker; no window document is decoded.
    // The row's own deletion, applied here or accepted and awaiting its
    // retry, is its `df:` fence (or `dt:` once hard), whatever the payload
    // length or a window's mutable tombstone map say.
    Ok(
        crate::deletion::row_deletion_marked(dbs, txn, id, raw.as_deref())?
            || dbs
                .vault_meta()
                .get(txn, &super::integrity::tombstone_key(id))?
                .is_some()
            || match raw {
                // A local delete whose publication is pending.
                Some(raw) => {
                    let window = crate::deletion::deletion_window_for_row(dbs, txn, id, &raw)?;
                    dbs.port_pending_tombstone_present(txn, WindowAddress::new(&window), id)?
                }
                None => false,
            },
    )
}
impl TombstoneStoreRead for Vault {
    fn port_tombstone_records<'a>(
        &self,
        txn: &'a RoTxn<'_>,
        family: super::DeletionFamily,
    ) -> Result<super::PortRows<'a, (EntityId, crate::deletion::DecodedTombstoneValue)>> {
        self.store.port_tombstone_records(txn, family)
    }

    fn port_deletion_state(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<DeletionState> {
        self.store.port_deletion_state(txn, id)
    }

    fn port_deletion_marker(
        &self,
        txn: &RoTxn<'_>,
        marker: DeletionMarker,
        id: &EntityId,
    ) -> Result<Option<Vec<u8>>> {
        self.store.port_deletion_marker(txn, marker, id)
    }

    fn port_deletion_marked(
        &self,
        txn: &RoTxn<'_>,
        marker: DeletionMarker,
        id: &EntityId,
    ) -> Result<bool> {
        self.store.port_deletion_marked(txn, marker, id)
    }
}
