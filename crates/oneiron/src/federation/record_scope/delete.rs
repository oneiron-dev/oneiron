//! The scoped delete door: selection and delete in one write transaction.

use super::*;

impl Vault {
    /// Selection and delete share one write transaction; no row can change between them.
    pub fn delete_records_in_scope(
        &self,
        selector: &Scope,
        slip: &Scope,
        channel: &Scope,
    ) -> Result<Vec<EntityId>> {
        self.with_write_txn_grouped(|txn| {
            let mut ids = Vec::new();
            for row in crate::ports::EntityStoreRead::port_entity_raw_records(&self.store, txn)? {
                let (id, raw) = row?;
                let h = EntityMetadataHeader::parse(&raw)
                    .ok_or(Error::CorruptedIndex("record header"))?;
                if let Some(scope) = stored_scope(&self.store, txn, id, h.entity_type)?
                    && note_world::admits_at(
                        &self.store,
                        txn,
                        id,
                        h.entity_type,
                        &scope,
                        [selector, slip, channel],
                        "delete",
                    )
                {
                    ids.push(id);
                }
            }
            let mut batch = self.batch_in();
            for id in &ids {
                batch = batch.delete(id);
            }
            batch.apply(txn)?;
            for id in &ids {
                retire_stamp(&self.store, txn, *id)?;
            }
            Ok(ids)
        })
    }
}
