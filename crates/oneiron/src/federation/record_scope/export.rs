//! The scoped export door.
use super::{Scope, ScopedRecord, admits, disclosure_scope_for_stored_row};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::provenance::birth::{WithheldKey, row_birth_in_txn};
use crate::{
    Vault,
    error::{Error, Result},
};

impl Vault {
    /// Export never has a debug mode and requires the export verb class, and
    /// never carries a SECRET_CUSTODY row or an unpublished LFS chunk.
    /// A row a device-only world keeps on this device is never exported, nor
    /// a text written from one, nor a row whose own words are withdrawn.
    pub fn export_records_in_scope(
        &self,
        selector: &Scope,
        slip: &Scope,
        channel: &Scope,
    ) -> Result<Vec<ScopedRecord>> {
        let txn = self.store.env.read_txn()?;
        let device_only = crate::settings::device_local_worlds_at(
            self,
            &txn,
            crate::claim::CallerLocality::OffDevice,
        )?;
        let withheld = |source: &crate::EntityId| {
            crate::settings::device_only_withholds(&self.store, &txn, &device_only, source)
        };
        let mut out = Vec::new();
        for row in crate::ports::EntityStoreRead::port_entity_raw_records(&self.store, &txn)? {
            let (id, raw) = row?;
            if withheld(&id)? || !crate::ports::raw_readable_in_txn(&self.store, &txn, &id, &raw)? {
                continue;
            }
            let h =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("record header"))?;
            if h.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY
                || crate::secret_custody::holds_masked_keys_in_txn(
                    &self.store,
                    &txn,
                    h.entity_type,
                    &raw[ENTITY_METADATA_HEADER_LEN..],
                )?
                || crate::origin::lfs::unpublished_lfs_chunk_in_txn(
                    &self.store,
                    &txn,
                    &id,
                    h.entity_type,
                )?
            {
                continue;
            }
            if let Some(scope) = disclosure_scope_for_stored_row(
                &self.store,
                &txn,
                id,
                h.entity_type,
                &raw[ENTITY_METADATA_HEADER_LEN..],
            )? && admits(&scope, selector, slip, channel, "export")
                && crate::authority::row_causal_admitted(self, &txn, &id, &raw)?
                && self.epoch_fence_in(&txn, id, &raw, [selector, slip, channel], "export")?
                && self.text_fence_in(
                    &txn,
                    id,
                    &raw,
                    [selector, slip, channel],
                    "export",
                    &withheld,
                )?
            {
                out.push(ScopedRecord {
                    id,
                    bytes: raw,
                    scope: Some(scope),
                    suppressed: false,
                    birth: None,
                });
            }
        }
        // A birth leaves naming only the rows this export carries; one key
        // per export, so its handles link to no other copy.
        let ships: std::collections::BTreeSet<crate::EntityId> =
            out.iter().map(|record| record.id).collect();
        let key = WithheldKey::for_export();
        for record in &mut out {
            record.birth = row_birth_in_txn(&self.store, &txn, &record.id)?
                .map(|birth| birth.masked(|row| ships.contains(row), &key));
        }
        Ok(out)
    }
}
