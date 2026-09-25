//! Transaction-local visibility ledger for canonical and composed session views.
use super::{DeletionState, TombstoneStoreRead};
use crate::{
    EntityId, Vault,
    error::{Error, Result},
    store::ManifestDbs,
};
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
        let deleted = archived
            || self
                .sync_state()
                .get(txn, crate::deletion::local_hard_delete_key(id).as_str())?
                .is_some()
            || self
                .vault_meta()
                .get(txn, &super::integrity::tombstone_key(id))?
                .is_some();
        let stale = super::integrity::stale_in_txn(self, txn, id)?;
        if deleted {
            return Ok(DeletionState {
                archived,
                deleted,
                stale,
            });
        }
        let Some(raw) = self.entities().get(txn, id.as_bytes())? else {
            return Ok(DeletionState {
                archived,
                deleted,
                stale,
            });
        };
        let h = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("entity header"))?;
        let window = crate::deletion::window_label_from_timestamp(h.learned_at);
        let key = crate::deletion::pending_tombstone_key(&window, id);
        if self.sync_state().get(txn, &key)?.is_some() {
            return Ok(DeletionState {
                archived,
                deleted: true,
                stale,
            });
        }
        #[cfg(feature = "sync")]
        let deleted = {
            use crate::sync::loro_support::{
                doc_from_snapshot, import_doc, tombstone_map_contains_id,
            };
            let key = format!("d:w:{window}");
            if let Some(snapshot) = self.sync_state().get(txn, &key)? {
                let doc = doc_from_snapshot(&snapshot)?;
                for entry in self
                    .sync_state()
                    .prefix_iter(txn, &format!("u:w:{window}:"))?
                {
                    let (_, update) = entry?;
                    import_doc(&doc, &update)?;
                }
                tombstone_map_contains_id(&doc.get_map("tombstones"), id)
            } else {
                false
            }
        };
        Ok(DeletionState {
            archived,
            deleted,
            stale,
        })
    }
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
