//! Edge weight and registry kind lookups for structural puts.

use crate::edge::EdgeKind;
use crate::memory::{MemoryError, MemoryResult};
use crate::registry::ENTITY_TYPE_REGISTRY;
/// The contract's registered stored prior for `kind`, falling back to the same
/// `1.0` [`Memory::put_structural`] uses for the three kinds whose
/// `pprWeight` column is null (`child_of` / `assigned_to` / `blocked_by`).
pub(super) fn registered_edge_weight(kind: EdgeKind) -> f32 {
    kind.default_weight().unwrap_or(1.0)
}
pub(super) fn type_byte_for_kind(kind: &str) -> MemoryResult<u8> {
    ENTITY_TYPE_REGISTRY
        .iter()
        .find(|entry| entry.kind == kind)
        .map(|entry| entry.type_byte)
        .ok_or_else(|| {
            MemoryError::bad_request_with(
                format!("unknown entity kind {kind:?}"),
                &["Use a registry kind string such as MESSAGE, PERSON, TASK, ASSET."],
            )
        })
}
pub(in crate::memory) fn kind_string_for_type(entity_type: u8) -> String {
    crate::registry::entity_type_registry_entry(entity_type).map_or_else(
        || format!("TYPE_{entity_type}"),
        |entry| entry.kind.to_owned(),
    )
}
