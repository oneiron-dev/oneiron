//! Canonical graph relation tokens shared by facade and outcome bindings.

use super::EdgeKind;

pub(crate) fn parse_relation(value: &str) -> Option<EdgeKind> {
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
