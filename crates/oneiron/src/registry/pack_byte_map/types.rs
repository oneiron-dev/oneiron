//! Name-bearing portable kinds, local registrations, and instance envelopes.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[doc(hidden)]
pub(super) use oneiron_records::registry::pack_byte_map::types::invalid;
#[doc(hidden)]
pub use oneiron_records::registry::pack_byte_map::types::{
    PackInstanceEnvelope, PackInstanceOrigin, PackKindIdentity, PackKindRegistration,
};

/// Where an allocated compiled-in kind lives: its own compiled-product slot,
/// or, once its family and that zone's overflow are full, the pack half
/// through PackByteMap (ARCH-0058 `#fail-soft`), name-bearing: its
/// instances are written by name (`Vault::put_pack_instance`), so a shared
/// overflow handle never stands for the kind alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StructuralKindAllocation {
    /// A compiled-product slot of its own.
    Compiled(crate::registry::StructuralKindRegistration),
    /// A PackByteMap registration under the kind's name-bearing identity.
    Pack(PackKindRegistration),
}

/// Sync/export carrier. This is DATA, never permission to execute a pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackByteMapSnapshot {
    pub version: u8,
    /// Random local map lineage id, NOT an authority-chain vault id.
    #[serde(with = "super::hex_bytes")]
    pub map_id: [u8; 16],
    pub revision: u64,
    pub registrations: BTreeMap<String, PackKindRegistration>,
    pub slot_generations: BTreeMap<u8, u64>,
}
