//! Hydrated entity value consumed by pack serializers.

use oneiron_base::edge::EdgeInfo;
use oneiron_contracts::entity_id::EntityId;
use std::collections::HashMap;

/// Hydrated entity with decoded fields, edges, and provenance.
#[derive(Debug, Clone)]
pub struct ContextEntity {
    pub id: EntityId,
    pub short_id: String,
    pub content_hash: u8,
    /// Exact document frontier which supplied these fields. A scoped consumer
    /// must gate this revision as well as the current entity's authority.
    pub source_revision_ref: Option<[u8; 16]>,
    pub entity_type: u8,
    pub score: f32,
    /// Predicate-class priority resolved from the vault manifest at hydration.
    /// This never changes claim visibility, scope, or budget ceilings.
    pub critical: bool,
    pub fields: Option<HashMap<String, serde_json::Value>>,
    pub edges: Option<Vec<EdgeInfo>>,
    pub vector: Option<Vec<f32>>,
}
