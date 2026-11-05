//! The row keys of a policy manifest's trusted-origin and seeded-confidence
//! side tables, spelled for the vault-bootstrap seed's raw write.

use oneiron_contracts::entity_id::EntityId;

/// The vault-bootstrap seed writes this row directly, before any vault (and so
/// any typed door) exists to read it back through: a plain string builder, so
/// that raw write keeps landing under the trusted-origin side table's declared
/// prefix byte-for-byte.
#[must_use]
pub fn trusted_manifest_key(id: &EntityId) -> String {
    format!("manifest:trusted:{}", id.to_hex())
}

/// The bootstrap seed's seeded-confidence row key, spelled for the same raw
/// write as [`trusted_manifest_key`].
#[must_use]
pub fn seeded_manifest_key(id: &EntityId) -> String {
    format!("manifest:seeded_confidence:{}", id.to_hex())
}
