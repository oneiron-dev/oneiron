//! Core half of `batch::export::export_enumerate`: its store-layer items live in `oneiron_store::batch::export::export_enumerate` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::batch::export::export_enumerate::*;

use super::whole_vault_export_excludes_entity_in_txn;
use crate::batch::EntityMetadataHeader;
use crate::{EntityId, Error, Result, Vault};

impl Vault {
    /// Walks every entity row in one read snapshot. There is no type whitelist,
    /// approval filter, or refusal merely because an off-record room is open.
    pub fn whole_vault_export_rows(&self) -> Result<Vec<WholeVaultExportRow>> {
        let txn = self.store.env.read_txn()?;
        let mut rows = Vec::new();
        for row in crate::ports::EntityStoreRead::port_entity_raw_records(&self.store, &txn)? {
            let (entity_id, raw) = row?;
            if whole_vault_export_excludes_entity_in_txn(&self.store, &txn, &entity_id)? {
                continue;
            }
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("export entity header"))?;
            rows.push(WholeVaultExportRow {
                entity_id,
                entity_type: header.entity_type,
            });
        }
        Ok(rows)
    }
}
