//! Local installation commands and name-based instance admission.

use super::persistence::{persist, read};
use super::types::{
    PackByteMapSnapshot, PackInstanceEnvelope, PackKindIdentity, PackKindRegistration, invalid,
};
use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::entity_id::EntityId;
use crate::error::{Error, RegistryError, Result};
use crate::registry::{TypeByteZone, zone_of};
use crate::store::Store;
use crate::temporal::TimeRange;
use heed::{RoTxn, RwTxn};
use std::collections::BTreeSet;

impl Vault {
    /// Explicit local installation, not a foreign-data import door.
    /// The caller must first approve and persist the exact package source.
    /// Hashes bind identity; this API mints NO execution grant or trust verdict.
    /// The complete list is atomic under the LMDB writer lock.
    pub(crate) fn install_pack_kinds_in_txn(
        &self,
        txn: &mut RwTxn<'_>,
        kinds: &[PackKindIdentity],
    ) -> Result<Vec<PackKindRegistration>> {
        let mut names = BTreeSet::new();
        for kind in kinds {
            kind.validate()?;
            if !names.insert(kind.name.as_str()) {
                return Err(Error::Registry(RegistryError::PackKindNameCollision(
                    kind.name.clone(),
                )));
            }
        }
        let mut map = read(&self.store, txn)?.unwrap_or_else(PackByteMapSnapshot::empty);
        let mut result = Vec::with_capacity(kinds.len());
        for kind in kinds {
            result.push(map.install(kind)?);
        }
        if !kinds.is_empty() {
            persist(self, txn, &mut map)?;
        }
        Ok(result)
    }

    #[cfg(test)]
    pub(super) fn install_pack_kinds(
        &self,
        kinds: &[PackKindIdentity],
    ) -> Result<Vec<PackKindRegistration>> {
        self.with_write_txn(|txn| self.install_pack_kinds_in_txn(txn, kinds))
    }

    /// Data snapshot, including retired name identities and generation history.
    /// Copying it to another vault does not install its kinds there.
    pub fn pack_byte_map_snapshot(&self) -> Result<Option<PackByteMapSnapshot>> {
        let txn = self.store.env.read_txn()?;
        read(&self.store, &txn)
    }

    pub fn pack_kind_registration(&self, name: &str) -> Result<Option<PackKindRegistration>> {
        Ok(self
            .pack_byte_map_snapshot()?
            .and_then(|map| map.registrations.get(name).cloned()))
    }

    /// Disable new instance writes, retaining the handle while rows refer to it.
    pub fn uninstall_pack_kind(&self, name: &str) -> Result<()> {
        self.with_write_txn(|txn| {
            let mut map = read(&self.store, txn)?.ok_or_else(|| {
                Error::Registry(RegistryError::PackKindNotInstalled(name.to_owned()))
            })?;
            let row = map.registrations.get_mut(name).ok_or_else(|| {
                Error::Registry(RegistryError::PackKindNotInstalled(name.to_owned()))
            })?;
            if row.active {
                row.active = false;
                persist(self, txn, &mut map)?;
            }
            Ok(())
        })
    }

    /// Return an inactive slot only after all active-store references are gone.
    /// Soft-deleted shells count. Historic sync bodies remain name-bearing and
    /// can never be decoded as the later occupant of a recycled slot.
    pub fn gc_pack_kind(&self, name: &str) -> Result<bool> {
        self.with_write_txn(|txn| {
            let Some(mut map) = read(&self.store, txn)? else {
                return Ok(false);
            };
            let Some(row) = map.registrations.get(name) else {
                return Ok(false);
            };
            if row.active {
                return Err(invalid("cannot collect an installed pack kind"));
            }
            let Some(handle) = row.handle else {
                return Ok(false);
            };
            // The entity table, not a possibly stale secondary type index,
            // is the proof. Header-only shells deliberately block reuse.
            for entry in self.store.entities.iter(txn)? {
                let (_, bytes) = entry?;
                let header = EntityMetadataHeader::parse(&bytes).ok_or(Error::CorruptedIndex(
                    "entity header during pack handle collection",
                ))?;
                if header.entity_type == handle {
                    if handle != super::state::SHARED_HANDLE {
                        return Ok(false);
                    }
                    // A shell or malformed body cannot prove which subtype it held.
                    let body = &bytes[crate::batch::ENTITY_METADATA_HEADER_LEN..];
                    match PackInstanceEnvelope::from_bytes(body) {
                        Ok(envelope) if envelope.kind.name != name => {}
                        _ => return Ok(false),
                    }
                }
            }
            map.registrations
                .get_mut(name)
                .ok_or_else(|| invalid("pack kind disappeared"))?
                .handle = None;
            persist(self, txn, &mut map)?;
            Ok(true)
        })
    }

    /// Write name-bound data through the ordinary batch pipeline. An installed
    /// shape is not an execution grant; pack behavior has its own policy gates.
    pub fn put_pack_instance(
        &self,
        id: &EntityId,
        name: &str,
        occurred: TimeRange,
        learned_at: u64,
        payload: &[u8],
    ) -> Result<()> {
        self.with_write_txn(|txn| {
            let map = read(&self.store, txn)?.ok_or_else(|| {
                Error::Registry(RegistryError::PackKindNotInstalled(name.to_owned()))
            })?;
            let (handle, envelope) = map.envelope(name, payload)?;
            self.batch_in()
                .put(id, handle, occurred, learned_at, &envelope.to_bytes()?)
                .apply(txn)
        })
    }

    /// Import data by global identity. No source-local byte or generation can
    /// install code, overwrite a name, or pick a local kind. Installation is a
    /// separate, explicit local command. Original lineage stays byte-faithful.
    pub fn import_pack_instance(
        &self,
        id: &EntityId,
        source: &PackInstanceEnvelope,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        self.with_write_txn(|txn| {
            let (handle, envelope) = self.store.remap_pack_instance_in_txn(txn, source)?;
            self.batch_in()
                .put(id, handle, occurred, learned_at, &envelope.to_bytes()?)
                .apply(txn)
        })
    }
}

impl Store {
    /// An occupied runtime entity id keeps its global kind identity, including
    /// when a caller tries to replace it with a compiled kind or another subtype.
    pub(crate) fn guard_pack_instance_identity_in_txn(
        &self,
        txn: &RoTxn<'_>,
        id: &EntityId,
        entity_type: u8,
        data: &[u8],
    ) -> Result<()> {
        let Some(raw) = self.entities.get(txn, id.as_bytes())? else {
            return Ok(());
        };
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("pack instance prior header"))?;
        if zone_of(header.entity_type) != TypeByteZone::PackHandle {
            return Ok(());
        }
        if zone_of(entity_type) != TypeByteZone::PackHandle {
            return Err(invalid("runtime entity kind cannot be replaced"));
        }
        let prior =
            PackInstanceEnvelope::from_bytes(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])?;
        let next = PackInstanceEnvelope::from_bytes(data)?;
        if prior.kind != next.kind {
            return Err(invalid("runtime entity global kind identity changed"));
        }
        Ok(())
    }

    /// An imported ASSET cannot replace the carrier the LOCAL head pins.
    /// Other assets and historical snapshots remain ordinary data.
    pub(crate) fn guard_pack_map_carrier_put_in_txn(
        &self,
        txn: &RoTxn<'_>,
        id: &EntityId,
        entity_type: u8,
        bytes: &[u8],
    ) -> Result<()> {
        let Some(pin) = super::persistence::HEAD_PIN.get(self, txn, &())? else {
            return Ok(());
        };
        let hash = pin.0;
        if super::persistence::carrier_id(&hash)? == *id
            && (entity_type != crate::registry::ENTITY_TYPE_ASSET
                || blake3::hash(bytes).as_bytes() != &hash)
        {
            return Err(invalid("local pack map carrier is immutable"));
        }
        Ok(())
    }

    /// Only the current local head is custody-protected; previous snapshots
    /// may be collected after a newer head commits.
    pub(crate) fn guard_pack_map_carrier_delete_in_txn(
        &self,
        txn: &RoTxn<'_>,
        id: &EntityId,
    ) -> Result<()> {
        let Some(pin) = super::persistence::HEAD_PIN.get(self, txn, &())? else {
            return Ok(());
        };
        if super::persistence::carrier_id(&pin.0)? == *id {
            return Err(invalid("current local pack map carrier cannot be deleted"));
        }
        Ok(())
    }

    pub(crate) fn validate_pack_handle_in_txn(&self, txn: &RoTxn<'_>, handle: u8) -> Result<()> {
        if zone_of(handle) != TypeByteZone::PackHandle {
            return Err(Error::InvalidEntityType(handle));
        }
        let map = read(self, txn)?.ok_or(Error::InvalidEntityType(handle))?;
        if map
            .registrations
            .values()
            .any(|row| row.active && row.handle == Some(handle))
        {
            Ok(())
        } else {
            Err(Error::InvalidEntityType(handle))
        }
    }

    /// Mandatory final body check for public, raw, replay and rematerialization.
    /// Non-pack kinds are untouched. `kind_reg:` rows never participate.
    pub(crate) fn validate_pack_instance_in_txn(
        &self,
        txn: &RoTxn<'_>,
        handle: u8,
        bytes: &[u8],
    ) -> Result<()> {
        if zone_of(handle) != TypeByteZone::PackHandle {
            return Ok(());
        }
        let map = read(self, txn)?.ok_or(Error::InvalidEntityType(handle))?;
        let envelope = PackInstanceEnvelope::from_bytes(bytes)?;
        map.validate_instance(handle, &envelope)?;
        // JSON byte arrays must not hide credentials from the standing scanner.
        crate::batch::secret_scan::scan_metadata_field(&String::from_utf8_lossy(
            &envelope.payload,
        ))?;
        Ok(())
    }

    pub(crate) fn remap_pack_instance_in_txn(
        &self,
        txn: &RoTxn<'_>,
        source: &PackInstanceEnvelope,
    ) -> Result<(u8, PackInstanceEnvelope)> {
        let map = read(self, txn)?.ok_or_else(|| {
            Error::Registry(RegistryError::PackKindNotInstalled(
                source.kind.name.clone(),
            ))
        })?;
        map.remap(source)
    }

    pub(crate) fn pack_short_id_prefix_in_txn(
        &self,
        txn: &RoTxn<'_>,
        handle: u8,
        bytes: &[u8],
    ) -> Result<String> {
        let map = read(self, txn)?.ok_or(Error::InvalidEntityType(handle))?;
        let envelope = PackInstanceEnvelope::from_bytes(bytes)?;
        map.validate_instance(handle, &envelope)?;
        Ok(envelope.kind.short_id_prefix())
    }
}
