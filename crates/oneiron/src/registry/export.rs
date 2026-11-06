//! Engine-owned kind/family/zone export (FIX 7830).
//!
//! Borrows the live registry tables and derives zone ranges from `zone_of`;
//! no allocation table is duplicated here.

use oneiron_contracts::registry::{
    ENTITY_TYPE_REGISTRY, EntityTypeRegistryEntry, TYPE_BYTE_FAMILIES, TypeByteFamilyEntry,
    TypeByteZone, zone_of,
};

/// Engine registry snapshot: storage ABI plus live kind/family tables and
/// zone ranges folded from `zone_of`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RegistrySnapshot {
    pub storage_abi_version: u16,
    pub kinds: &'static [EntityTypeRegistryEntry],
    pub families: &'static [TypeByteFamilyEntry],
    pub zones: Vec<ZoneRow>,
}

/// One zone plus its byte ranges, folded from `zone_of` over `0..=255`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ZoneRow {
    pub zone: TypeByteZone,
    pub ranges: Vec<(u8, u8)>,
}

/// Builds the current registry snapshot. No vault required.
#[must_use]
pub fn registry_snapshot() -> RegistrySnapshot {
    let mut zones: Vec<ZoneRow> = Vec::new();
    for byte in 0..=255u16 {
        let byte = byte as u8;
        let zone = zone_of(byte);
        match zones.iter_mut().find(|row| row.zone == zone) {
            Some(row) => {
                if let Some(last) = row.ranges.last_mut() {
                    if last.1.checked_add(1) == Some(byte) {
                        last.1 = byte;
                    } else {
                        row.ranges.push((byte, byte));
                    }
                } else {
                    row.ranges.push((byte, byte));
                }
            }
            None => zones.push(ZoneRow {
                zone,
                ranges: vec![(byte, byte)],
            }),
        }
    }
    RegistrySnapshot {
        storage_abi_version: crate::store::STORAGE_ABI_VERSION,
        kinds: ENTITY_TYPE_REGISTRY,
        families: TYPE_BYTE_FAMILIES,
        zones,
    }
}
