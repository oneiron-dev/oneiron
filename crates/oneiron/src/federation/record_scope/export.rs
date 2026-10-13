//! The scoped export door.
use super::{Scope, ScopedRecord, admits, disclosure_scope_for_stored_row};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::{
    Vault,
    error::{Error, Result},
};

impl Vault {
    /// Export never has a debug mode and requires the export verb class.
    /// A row a device-only world keeps on this device is never exported.
    pub fn export_records_in_scope(
        &self,
        selector: &Scope,
        slip: &Scope,
        channel: &Scope,
    ) -> Result<Vec<ScopedRecord>> {
        let txn = self.store.env.read_txn()?;
        let device_only = crate::settings::device_local_worlds_at(
            &self.store,
            &txn,
            crate::claim::CallerLocality::OffDevice,
        )?;
        let mut out = Vec::new();
        for row in crate::ports::EntityStoreRead::port_entity_raw_records(&self.store, &txn)? {
            let (id, raw) = row?;
            if crate::settings::device_only_withholds(&self.store, &txn, &device_only, &id)? {
                continue;
            }
            let h =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("record header"))?;
            if let Some(scope) = disclosure_scope_for_stored_row(
                &self.store,
                &txn,
                id,
                h.entity_type,
                &raw[ENTITY_METADATA_HEADER_LEN..],
            )? && admits(&scope, selector, slip, channel, "export")
                && crate::authority::row_causal_admitted(self, &txn, &id, &raw)?
            {
                out.push(ScopedRecord {
                    id,
                    bytes: raw,
                    scope: Some(scope),
                    suppressed: false,
                });
            }
        }
        Ok(out)
    }
}
