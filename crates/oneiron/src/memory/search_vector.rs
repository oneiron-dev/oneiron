//! Typed vector search in the caller's ordinary credential-bound lane.
use serde::{Deserialize, Serialize};
use super::{Memory, MemoryError, MemoryResult, caps};
use crate::claim::{ClaimReadStatus, ScopedReadResult};
use crate::embed::{EmbeddingMatchEvidence, InputKind};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VectorSearchRequest {
    /// Omit for the vault's text index; otherwise the complete declared pin.
    #[serde(default)]
    pub space: Option<String>,
    #[serde(default)]
    pub query_kind: Option<InputKind>,
    pub query: Vec<f32>,
    /// Stored input kinds in a declared space, not registry kinds.
    #[serde(default)]
    pub kinds: Vec<InputKind>,
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct VectorSearchHit {
    pub entity_ref: String,
    pub source_revision_ref: Option<String>,
    /// Rank score within this space only, never compared across spaces.
    pub score: f32,
    pub embedding_matches: Vec<EmbeddingMatchEvidence>,
}

impl VectorSearchRequest {
    pub fn validate(&self) -> MemoryResult<()> {
        caps::check_limit_nonzero(self.limit)?;
        caps::check_dimensions(self.query.len())?;
        if self.query.iter().any(|value| !value.is_finite()) {
            return Err(MemoryError::bad_request("query must be a finite vector"));
        }
        if self.space.is_none() && (self.query_kind.is_some() || !self.kinds.is_empty()) {
            return Err(MemoryError::bad_request("query_kind and kinds name a declared space; set space too"));
        }
        Ok(())
    }
}

impl Memory<'_> {
    pub fn query_vector(&self, input: &VectorSearchRequest) -> MemoryResult<ScopedReadResult<Vec<VectorSearchHit>>> {
        input.validate()?;
        let lane = self.read_lane(ClaimReadStatus::Surfaceable)?;
        let (limit, _) = caps::clamp_search_limit(input.limit);
        let result = match &input.space {
            Some(space) => lane.search_space_kinds_revisioned(
                space, input.query_kind.unwrap_or(InputKind::Text), &input.query, &input.kinds, limit, None,
            ),
            None => lane.search_vector_revisioned(&input.query, limit, None),
        }?;
        self.produced_from(result.hits.iter().map(|hit| hit.id));
        Ok(ScopedReadResult {
            value: result.hits.into_iter().map(|hit| VectorSearchHit {
                entity_ref: hit.id.to_hex(),
                source_revision_ref: result.revisions.get(&hit.id).map(|revision| revision.to_hex()),
                score: hit.score,
                embedding_matches: result.embedding_matches.get(&hit.id).cloned().unwrap_or_default(),
            }).collect(),
            receipt: result.receipt,
        })
    }
}
