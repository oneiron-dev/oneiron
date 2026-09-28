//! Trusted, transaction-local LMDB staging beneath admitted batch and repair doors.
use super::{EdgeStoreInventory, EdgeStoreStaging, EntityStoreStaging, PortRows};
use crate::error::Result;
use crate::store::{ManifestDbs, Store};
use crate::{EdgeKind, EntityId};
use heed::RwTxn;

impl<T: ManifestDbs> EntityStoreStaging for T {
    fn port_stage_entity_row(
        &self,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
        encoded: &[u8],
    ) -> Result<()> {
        self.entities().put(txn, id.as_bytes(), encoded)?;
        Ok(())
    }

    fn port_remove_entity_row(&self, txn: &mut RwTxn<'_>, id: &EntityId) -> Result<bool> {
        self.entities().delete(txn, id.as_bytes())
    }
}

impl<T: ManifestDbs> EdgeStoreStaging for T {
    fn port_edge_encoded(
        &self,
        txn: &heed::RoTxn<'_>,
        src: &EntityId,
        kind: EdgeKind,
        dst: &EntityId,
    ) -> Result<Option<Vec<u8>>> {
        let out = Store::encode_edge_key(src, kind, dst);
        Ok(self.edges_out().get(txn, &out)?.map(|value| value.to_vec()))
    }
    fn port_stage_edge_rows(
        &self,
        txn: &mut RwTxn<'_>,
        src: &EntityId,
        kind: EdgeKind,
        dst: &EntityId,
        encoded: &[u8],
    ) -> Result<()> {
        let out = Store::encode_edge_key(src, kind, dst);
        let incoming = Store::encode_edge_key(dst, kind, src);
        self.edges_out().put(txn, &out, encoded)?;
        self.edges_in().put(txn, &incoming, encoded)?;
        Ok(())
    }

    fn port_remove_edge_rows(
        &self,
        txn: &mut RwTxn<'_>,
        src: &EntityId,
        kind: EdgeKind,
        dst: &EntityId,
    ) -> Result<bool> {
        let out = Store::encode_edge_key(src, kind, dst);
        let incoming = Store::encode_edge_key(dst, kind, src);
        let removed = self.edges_out().delete(txn, &out)?;
        self.edges_in().delete(txn, &incoming)?;
        Ok(removed)
    }
}

impl<T: ManifestDbs> EdgeStoreInventory for T {
    fn port_edge_rows_raw<'a>(
        &self,
        txn: &'a heed::RoTxn<'_>,
    ) -> Result<PortRows<'a, (Vec<u8>, Vec<u8>)>> {
        Ok(Box::new(self.edges_out().iter(txn)?.map(|row| {
            let (key, value) = row?;
            Ok((key.to_vec(), value.to_vec()))
        })))
    }
}

impl EdgeStoreInventory for crate::Vault {
    fn port_edge_rows_raw<'a>(
        &self,
        txn: &'a heed::RoTxn<'_>,
    ) -> Result<PortRows<'a, (Vec<u8>, Vec<u8>)>> {
        self.store.port_edge_rows_raw(txn)
    }
}
