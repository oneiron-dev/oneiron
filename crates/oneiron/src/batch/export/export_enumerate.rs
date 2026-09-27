//! Snapshot enumeration for whole-vault exports, independent of type whitelists.
use super::whole_vault_export_excludes_entity;
use crate::batch::EntityMetadataHeader;
use crate::{EntityId, Error, Result, Vault};

/// A row selected for export. Serialization owns credential nulling; this
/// enumerator returns identities, never raw credentials or unredacted bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WholeVaultExportRow {
    pub entity_id: EntityId,
    pub entity_type: u8,
}

impl Vault {
    /// Walks every entity row in one read snapshot. There is no type whitelist,
    /// approval filter, or refusal merely because an off-record room is open.
    pub fn whole_vault_export_rows(&self) -> Result<Vec<WholeVaultExportRow>> {
        let txn = self.store.env.read_txn()?;
        let mut rows = Vec::new();
        for row in crate::ports::EntityStoreRead::port_entity_raw_records(&self.store, &txn)? {
            let (entity_id, raw) = row?;
            if whole_vault_export_excludes_entity(self, &entity_id)? {
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
