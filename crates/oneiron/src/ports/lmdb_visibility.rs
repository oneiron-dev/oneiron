//! Transaction-local visibility ledger for canonical and composed session views.
use super::{DeletionState, TombstoneStoreRead};
use crate::{EntityId, Vault, error::Result, store::ManifestDbs};
use heed::RoTxn;
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
                    dbs.sync_state()
                        .get(txn, &crate::deletion::pending_tombstone_key(&window, id))?
                        .is_some()
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
}
