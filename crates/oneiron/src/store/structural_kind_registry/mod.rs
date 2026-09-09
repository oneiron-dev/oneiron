//! Vault-scoped dynamic entity-type/kind registry: registration, load and
//! rebuild, zone validation, and the type-byte re-key migration.

mod registry;
mod rekey;

pub(in crate::store) use self::registry::load_structural_kind_registry;
pub(in crate::store) use self::rekey::{TYPE_BYTE_REKEY_V3, rekey_type_bytes_v3_in_txn};
// Test-only seam (open_gates/mod.rs precedent): the store and crate test
// suites name these bare through `use super::*` / `use crate::store::{...}`,
// but no non-test code outside `structural_kind_registry/` reaches them
// through the seam, so the re-exports live under `cfg(test)`.
#[cfg(test)]
pub(crate) use self::registry::{
    STRUCTURAL_KIND_REGISTRY_KEY_PREFIX, STRUCTURAL_KIND_REGISTRY_RECORD_VERSION,
    structural_kind_registry_key,
};
#[cfg(test)]
pub(in crate::store) use self::registry::{
    STRUCTURAL_KIND_REGISTRY_RECORD_VERSION_PRE_V3, decode_structural_kind_registration,
};
