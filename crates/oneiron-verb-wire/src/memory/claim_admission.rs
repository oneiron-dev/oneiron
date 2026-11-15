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
    pub scope: ClaimScope,
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
