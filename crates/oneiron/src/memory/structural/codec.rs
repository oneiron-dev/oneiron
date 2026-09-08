//! Edge-kind string codec and registry kind lookups for structural puts.

use crate::edge::EdgeKind;
use crate::memory::{MemoryError, MemoryResult};
use crate::registry::ENTITY_TYPE_REGISTRY;
pub(crate) fn edge_kind_from_str(value: &str) -> Option<EdgeKind> {
    let kind = match value {
        "authored_by" => EdgeKind::AuthoredBy,
        "scoped_to" => EdgeKind::ScopedTo,
        "part_of" => EdgeKind::PartOf,
        "supersedes" => EdgeKind::Supersedes,
        "belongs_to" => EdgeKind::BelongsTo,
        "claim_of" => EdgeKind::ClaimOf,
        "child_of" => EdgeKind::ChildOf,
        "assigned_to" => EdgeKind::AssignedTo,
        "derived_from" => EdgeKind::DerivedFrom,
        "mentions" => EdgeKind::Mentions,
        "about" => EdgeKind::About,
        "supports" => EdgeKind::Supports,
        "opposes" => EdgeKind::Opposes,
        "participates_in" => EdgeKind::ParticipatesIn,
        "attached" => EdgeKind::Attached,
        "employed_by" => EdgeKind::EmployedBy,
        "has_facet" => EdgeKind::HasFacet,
        "facet_of" => EdgeKind::FacetOf,
        "in_world" => EdgeKind::InWorld,
        "set_in" => EdgeKind::SetIn,
        "merged_into" => EdgeKind::MergedInto,
        "split_into" => EdgeKind::SplitInto,
        "blocked_by" => EdgeKind::BlockedBy,
        "blocks" => EdgeKind::Blocks,
        "fulfills" => EdgeKind::Fulfills,
        "discharged_by" => EdgeKind::DischargedBy,
        "same_as" => EdgeKind::SameAs,
        _ => return None,
    };
    Some(kind)
}
/// The contract's registered stored prior for `kind`, falling back to the same
/// `1.0` [`Memory::put_structural`] uses for the three kinds whose
/// `pprWeight` column is null (`child_of` / `assigned_to` / `blocked_by`).
pub(crate) fn registered_edge_weight(kind: EdgeKind) -> f32 {
    kind.default_weight().unwrap_or(1.0)
}
pub(crate) fn type_byte_for_kind(kind: &str) -> MemoryResult<u8> {
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
pub(crate) fn kind_string_for_type(entity_type: u8) -> String {
    crate::registry::entity_type_registry_entry(entity_type).map_or_else(
        || format!("TYPE_{entity_type}"),
        |entry| entry.kind.to_owned(),
    )
}
