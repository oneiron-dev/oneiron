//! Moved from `crates/oneiron/src/memory/search_vector.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::embedding::EmbeddingMatchEvidence;
use serde::Deserialize;
use serde::Serialize;

/// The compatibility shape fixed when the vault opens. Changing a populated
/// graph's prefix is not an online operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct VectorSearchConfig {
    pub dimensions: usize,
    pub fast_dims: Option<u16>,
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum VectorSearchLane {
    #[default]
    Ordinary,
    /// Explicit speculative voice quality for the text index, at a reduced limit.
    VoiceHot,
}

/// The source revision is the same pin the dense lane retrieved. It can be
/// hydrated/cited without silently switching to newer text.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct VectorSearchHit {
    pub entity_ref: String,
    pub source_revision_ref: Option<String>,
    /// Rank score within this space only, never compared across spaces.
    pub score: f32,
    pub embedding_matches: Vec<EmbeddingMatchEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct VectorSearchResult {
    pub hits: Vec<VectorSearchHit>,
    pub lane: VectorSearchLane,
    pub effective_limit: usize,
    pub limit_clamped: bool,
    /// None for a declared embedding space or when authority prevented the
    /// text-index vector channel from running. Scores from different
    /// dimensional spaces are not cross-comparable.
    pub refinement: Option<oneiron_store::vector_refinement::VectorRefinement>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VectorPutRequest {
    pub entity_ref: String,
    /// Always the full stored width, never a truncated MRL prefix.
    pub vector: Vec<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct VectorPutReceipt {
    pub entity_ref: String,
    pub dimensions: usize,
}
