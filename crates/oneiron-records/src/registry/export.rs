//! Moved from `crates/oneiron/src/registry/export.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::registry::EntityTypeRegistryEntry;
use oneiron_contracts::registry::TypeByteFamilyEntry;
use oneiron_contracts::registry::TypeByteZone;

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
