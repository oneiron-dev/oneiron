//! LMDB/session adapter of the window deletion-row port, over the declared `sync_state` families.
use super::window_rows::PendingTombstoneRow;
use super::{PortRows, WindowAddress, WindowDeletionRows};
use crate::EntityId;
use crate::deletion::{PENDING_TOMBSTONE, PendingTombstoneKey};
use crate::error::Result;
use crate::store::ManifestDbs;
use heed::RoTxn;

fn pending_key(window: WindowAddress<'_>, id: &EntityId) -> PendingTombstoneKey {
    PendingTombstoneKey {
        window: window.as_str().to_owned(),
        id: *id,
    }
}

impl<T: ManifestDbs> WindowDeletionRows for T {
    fn port_pending_tombstone(
        &self,
        txn: &RoTxn<'_>,
        window: WindowAddress<'_>,
        id: &EntityId,
    ) -> Result<Option<Vec<u8>>> {
        PENDING_TOMBSTONE.get_bytes(self, txn, &pending_key(window, id))
    }

    fn port_pending_tombstone_present(
        &self,
        txn: &RoTxn<'_>,
        window: WindowAddress<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        PENDING_TOMBSTONE.contains(self, txn, &pending_key(window, id))
    }

    fn port_pending_tombstones_in_window<'a>(
        &self,
        txn: &'a RoTxn<'_>,
        window: WindowAddress<'_>,
    ) -> Result<PortRows<'a, PendingTombstoneRow>> {
        let prefix = format!("{}:", window.as_str());
        Ok(Box::new(
            PENDING_TOMBSTONE
                .iter_from(self, txn, prefix.as_bytes())?
                .map(|row| {
                    let (key, raw) = row?;
                    Ok(PendingTombstoneRow {
                        window_label: key.window,
                        id: key.id,
                        raw,
                    })
                }),
        ))
    }

    fn port_has_world_pending_tombstone(
        &self,
        txn: &RoTxn<'_>,
        month: WindowAddress<'_>,
    ) -> Result<bool> {
        let worlds = format!("{}@", month.as_str());
        Ok(PENDING_TOMBSTONE
            .iter_from(self, txn, worlds.as_bytes())?
            .next()
            .transpose()?
            .is_some())
    }

    #[cfg(feature = "sync")]
    fn port_window_doc_with_raw<R, F>(
        &self,
        txn: &RoTxn<'_>,
        window: WindowAddress<'_>,
        read: F,
    ) -> Result<Option<R>>
    where
        F: FnOnce(&[u8]) -> Result<R>,
    {
        self.sync_state()
            .get(txn, &format!("d:w:{}", window.as_str()))?
            .map(|raw| read(&raw))
            .transpose()
    }

    #[cfg(feature = "sync")]
    fn port_window_updates_raw<'a, R, F>(
        &self,
        txn: &'a RoTxn<'_>,
        window: WindowAddress<'_>,
        mut inspect: F,
    ) -> Result<PortRows<'a, R>>
    where
        R: 'a,
        F: FnMut(&str, &[u8]) -> R + 'a,
    {
        Ok(Box::new(
            self.sync_state()
                .prefix_iter(txn, &format!("u:w:{}:", window.as_str()))?
                .map(move |row| {
                    let (key, value) = row?;
                    Ok(inspect(&key, &value))
                }),
        ))
    }
}
