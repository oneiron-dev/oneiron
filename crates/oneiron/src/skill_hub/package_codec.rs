//! Bounded, typed package persistence. This is storage, not an export door.
use super::package::{MAX_HUB_FILE_BYTES, MAX_HUB_PACKAGE_TOTAL_BYTES};
use super::{HubFile, HubPackage, SkillCapabilitySurface, SkillPackageFormat};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::skill::{decode_skill_record, encode_skill_record};
use crate::{
    Vault,
    entity_id::EntityId,
    error::{ArtifactError, Error, Result},
};
use std::io::{Cursor, Read};

/// Persisted hub package sidecar (the MAGIC-framed envelope [`encode_hub_package`]
/// / [`decode_hub_package`] already spell) for a skill entity.
const PACKAGE: SideTable<EntityId, HubPackage, Raw> =
    SideTable::new(&side_table::SKILL_HUB_PACKAGE);

pub(super) use crate::store::skill_package::codec::{
    MAX_ENCODED, encoded_file_bytes, invalid, is_hub_package_envelope,
};
pub use crate::store::skill_package::codec::{decode_hub_package, encode_hub_package};

/// A same-tree metadata edit cannot claim different source identity. A real
/// hash change is allowed; the shared put stage physically retires its old
/// source and sidecar. The new carrier may precede or follow that update.
pub(super) fn check_source_binding_update(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    record: &crate::skill::SkillRecord,
    replaces_source: bool,
) -> Result<()> {
    if replaces_source {
        return Ok(());
    }
    if let Some(source) = PACKAGE.get(store, txn, id)?
        && record.content_hash == Some(source.content_hash()?)
        && (record.skill_id != source.record.skill_id
            || record.version != source.record.version
            || record.desc != source.record.desc
            || record.role != source.record.role
            || record.call != source.record.call)
    {
        return Err(invalid(
            "source-backed skill revision requires an owning source transaction",
        ));
    }
    Ok(())
}

impl Vault {
    pub(crate) fn persist_hub_package_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        entity: &EntityId,
        package: &HubPackage,
    ) -> Result<()> {
        let record = self.read_skill_record_in_txn(txn, entity)?;
        let hash = package.content_hash()?;
        if record.content_hash != Some(hash)
            || record.skill_id != package.record.skill_id
            || record.version != package.record.version
            || record.desc != package.record.desc
            || record.role != package.record.role
            || record.call != package.record.call
        {
            return Err(invalid("stored package differs from its native skill"));
        }
        // Validated early (hash drift, native-source binding) so a later
        // encode failure can never happen after the carrier maintenance
        // below has already run; `PACKAGE.put` re-derives the same bytes.
        encode_hub_package(package)?;
        // Same-transaction ordinary ASSET carrier: the replicated custody row
        // for this exact tree hash. The stamps are the skill's own header so
        // the carrier reads as contemporaneous evidence, not new activity.
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, entity)?
            .ok_or(Error::EntityNotFound)?;
        let header = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("skill row header"))?;
        let carrier = super::source_carrier::source_carrier_id(entity, &hash)?;
        let encoded_carrier = super::source_carrier::encode_source_carrier(entity, package)?;
        // Same content bytes, new record metadata (e.g. hub sync applies a
        // version bump over an unchanged file tree): the carrier id is derived
        // from holder + content hash, so skip the put entirely when a carrier
        // row already exists there — carriers are content-addressed immutable.
        // Credential-bearing trees skip too: the write-door secret scan would
        // refuse the carrier put, and a refused scan must not fail the import
        // — the scan verdict on the skill row is what gates activation.
        let carrier_dirty =
            crate::batch::secret_scan::scan_file_content("", &encoded_carrier).is_some();
        if !carrier_dirty
            && !crate::ports::EntityStoreRead::port_entity_present(&self.store, txn, &carrier)?
        {
            self.batch_in()
                .put(
                    &carrier,
                    crate::registry::ENTITY_TYPE_ASSET,
                    crate::temporal::TimeRange {
                        start: header.occurred_start,
                        end: header.occurred_end,
                    },
                    header.learned_at,
                    &encoded_carrier,
                )
                .apply(txn)?;
        }
        PACKAGE.put(&self.store, txn, entity, package)
    }
    /// Recovers the exact package from its replicated carrier when the local
    /// sidecar is absent after sync. Exact tree hash plus skill id, version
    /// and description must match the stored record; anything else fails
    /// closed instead of presenting near or foreign bytes as this skill.
    pub(crate) fn hub_package_from_carrier_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        entity: &EntityId,
        record: &crate::skill::SkillRecord,
    ) -> Result<Option<HubPackage>> {
        Ok(self
            .hub_package_from_carrier_sourced_in_txn(txn, entity, record)?
            .0)
    }
    /// The same fallback, carrying the source result even when a carrier is rejected.
    pub(crate) fn hub_package_from_carrier_sourced_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        entity: &EntityId,
        record: &crate::skill::SkillRecord,
    ) -> Result<(Option<HubPackage>, Option<Vec<EntityId>>)> {
        let Some(hash) = record.content_hash else {
            return Ok((None, Some(Vec::new())));
        };
        let carrier = super::source_carrier::source_carrier_id(entity, &hash)?;
        let (carried, sources) =
            super::source_carrier::read_source_carrier_sourced_in_txn(&self.store, txn, &carrier)?;
        let Some((holder, package)) = carried else {
            return Ok((None, sources));
        };
        if holder != *entity
            || package.content_hash()? != hash
            || package.record.skill_id != record.skill_id
            || package.record.version != record.version
            || package.record.desc != record.desc
            || package.record.role != record.role
            || package.record.call != record.call
        {
            return Err(invalid("replicated source differs from its native skill"));
        }
        Ok((Some(package), sources))
    }
    /// Instruction bytes for an admitted runtime load, never a standalone export door.
    pub(crate) fn runtime_skill_package_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        entity: &EntityId,
        record: &crate::skill::SkillRecord,
    ) -> Result<Option<HubPackage>> {
        Ok(self
            .runtime_skill_package_sourced_in_txn(txn, entity, record)?
            .0)
    }
    /// The native PACKAGE-first read beside the bodies supplying its result.
    /// A stored local PACKAGE has no EntityId body carrier, so its sources are unknown.
    pub(crate) fn runtime_skill_package_sourced_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        entity: &EntityId,
        record: &crate::skill::SkillRecord,
    ) -> Result<(Option<HubPackage>, Option<Vec<EntityId>>)> {
        let package = match PACKAGE.get(&self.store, txn, entity)? {
            Some(package) => package,
            None => return self.hub_package_from_carrier_sourced_in_txn(txn, entity, record),
        };
        super::source_custody::check_source_custody(
            &self.store,
            txn,
            entity,
            &package.content_hash()?,
        )?;
        if record.content_hash != Some(package.content_hash()?)
            || record.skill_id != package.record.skill_id
            || record.version != package.record.version
            || record.desc != package.record.desc
            || record.role != package.record.role
            || record.call != package.record.call
        {
            return Err(invalid("runtime package differs from the admitted skill"));
        }
        Ok((Some(package), None))
    }
    /// The replicated carrier ASSET a runtime load of `entity`'s package read
    /// its bytes from, on the load's snapshot (FIX 7017): `None` while the
    /// local sidecar holds them, which [`Self::runtime_skill_package_in_txn`]
    /// reads first, as part of the skill's own row.
    pub(crate) fn runtime_package_carrier_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        entity: &EntityId,
        record: &crate::skill::SkillRecord,
    ) -> Result<Option<EntityId>> {
        if PACKAGE.contains(&self.store, txn, entity)? {
            return Ok(None);
        }
        record
            .content_hash
            .map(|hash| super::source_carrier::source_carrier_id(entity, &hash))
            .transpose()
    }
    pub(super) fn hub_baseline_instructions(
        &self,
        txn: &heed::RoTxn<'_>,
        entity: &EntityId,
        record: &crate::skill::SkillRecord,
    ) -> Result<String> {
        let Some(package) = self.runtime_skill_package_in_txn(txn, entity, record)? else {
            if record.source == crate::claim::ClaimSource::Imported || record.forked_from.is_some()
            {
                return Err(invalid(
                    "imported or forked baseline has no stored instruction package",
                ));
            }
            return Ok(record.desc.clone());
        };
        if record.content_hash != Some(package.content_hash()?) {
            return Err(invalid("baseline package hash drift"));
        }
        let file = package
            .files
            .iter()
            .find(|file| file.path == "SKILL.md")
            .ok_or_else(|| invalid("baseline has no instructions"))?;
        String::from_utf8(file.content.clone())
            .map_err(|_| invalid("baseline instructions are not UTF-8"))
    }
    /// Internal snapshot access only. Callers must apply mandatory export nulling.
    /// The local sidecar answers first; only when it is absent does the
    /// replicated carrier answer, on exact hash plus record-metadata match.
    pub(crate) fn export_hub_package_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        entity: &EntityId,
    ) -> Result<Option<HubPackage>> {
        if self.store.off_record_sessions.contains_entity(entity)? {
            return Ok(None);
        }
        let crate::vault::LiveEntityRow::Live { entity_type, body } =
            crate::vault::live_entity_row_in_txn(&self.store, txn, entity)?
        else {
            return Ok(None);
        };
        if entity_type != crate::registry::ENTITY_TYPE_SKILL {
            return Ok(None);
        }
        let record = decode_skill_record(&body)?;
        self.runtime_skill_package_in_txn(txn, entity, &record)
    }
    /// The replicated carrier [`Self::export_hub_package_in_txn`] reads
    /// `entity`'s package from, for an export to judge by its locality filter
    /// and name among its sources (SCAN C022): `None` when the local sidecar
    /// answers, or when `record` admits no package hash.
    pub(crate) fn export_hub_package_carrier_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        entity: &EntityId,
        record: &crate::skill::SkillRecord,
    ) -> Result<Option<EntityId>> {
        if PACKAGE.contains(&self.store, txn, entity)? {
            return Ok(None);
        }
        record
            .content_hash
            .as_ref()
            .map(|hash| super::source_carrier::source_carrier_id(entity, hash))
            .transpose()
    }
    pub(super) fn stored_hub_package_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        entity: &EntityId,
    ) -> Result<HubPackage> {
        self.export_hub_package_in_txn(txn, entity)?
            .ok_or_else(|| invalid("skill has no stored package"))
    }
}

/// Payload erasure shared by physical purge and shell-preserving SoftErase.
pub(crate) fn remove_hub_package_in_txn(
    write: &crate::secret_custody::CustodyWrite<'_>,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let store = write.store;
    super::source_custody::remove_source_custody_in_txn(write, txn, id)
}

pub(super) fn remove_package_sidecar_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    PACKAGE.delete(store, txn, id)?;
    Ok(())
}

pub(super) fn remove_matching_package_sidecar_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    hash: &crate::skill::SkillContentHash,
) -> Result<()> {
    if let Some(package) = PACKAGE.get(store, txn, id)?
        && package
            .content_hash()
            .map_err(|_| Error::CorruptedIndex("stored source sidecar hash"))?
            == *hash
    {
        remove_package_sidecar_in_txn(store, txn, id)?;
    }
    Ok(())
}
