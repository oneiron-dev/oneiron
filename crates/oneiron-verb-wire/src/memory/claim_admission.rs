//! Moved from `crates/oneiron/src/memory/claim_admission.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The explicit relationship position: `all`, or a set of relationships.
/// An empty list is the explicit empty set, never `all`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum ClaimRelationships {
    All(AllRelationships),
    Relationships(Vec<String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AllRelationships {
    All,
}

/// A claim's position, never a credential ceiling. No axis is inferred when one is absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimScope {
    pub world_id: String,
    pub scope_facet_id: String,
    pub scope_relationship_id: ClaimRelationships,
    pub scope_project_id: String,
}

impl ClaimScope {
    pub fn of_body(body: &oneiron_store::write_envelope::claim_body::ClaimBody) -> Self {
        Self {
            world_id: body
                .world
                .unwrap_or_else(oneiron_store::write_envelope::claim_body::base_world_id)
                .to_hex(),
            scope_facet_id: body.scope_facet.to_hex(),
            scope_relationship_id: body
                .rel
                .as_ref()
                .map_or(ClaimRelationships::All(AllRelationships::All), |ids| {
                    ClaimRelationships::Relationships(ids.iter().map(|id| id.to_hex()).collect())
                }),
            scope_project_id: body.scope_project.to_hex(),
        }
    }
}

/// A claim's position as a caller sends it (OF-464; canon cross-arch-0002a
/// §5.8). Each axis may be omitted. Before the write lands, the write door
/// stamps an omitted axis from the caller's authorised context: the world
/// and facet the caller's credential is bound to, else the base WORLD, the
/// vault's default FACET (only while it is a stored FACET; otherwise the
/// write is refused and names `scope_facet_id`), `all` relationships, and
/// the root's default PROJECT. The stored and returned claim always carries
/// all four axes ([`ClaimScope`]); omission is never an untagged stored value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimScopeInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub world_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_facet_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_relationship_id: Option<ClaimRelationships>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_project_id: Option<String>,
}

impl From<ClaimScope> for ClaimScopeInput {
    /// A fully stated position: every axis named, nothing left to stamp.
    fn from(scope: ClaimScope) -> Self {
        Self {
            world_id: Some(scope.world_id),
            scope_facet_id: Some(scope.scope_facet_id),
            scope_relationship_id: Some(scope.scope_relationship_id),
            scope_project_id: Some(scope.scope_project_id),
        }
    }
}

/// Public claim admission. Provenance is host-authored; made_by is not an input field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopedClaimInput {
    pub id: Option<String>,
    pub predicate: String,
    pub subject_ref: String,
    pub value: serde_json::Value,
    pub confidence: f32,
    pub source: String,
    /// The claim's position; an omitted axis, or an omitted `scope`, is
    /// stamped by the write door ([`ClaimScopeInput`]).
    #[serde(default)]
    pub scope: ClaimScopeInput,
    /// Optional sensitivity band, in 0..=3, independent of the four position axes.
    pub sensitivity: Option<u8>,
    #[serde(default)]
    pub evidence_turn_refs: Vec<String>,
    pub valid_from: Option<u64>,
    pub valid_to: Option<u64>,
    pub occurred_at: Option<u64>,
    pub learned_at: Option<u64>,
    pub salience: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopedCommitRequest {
    pub claims: Vec<ScopedClaimInput>,
}
