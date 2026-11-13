//! Moved from `crates/oneiron/src/memory/search_vector.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use oneiron_store::embedding::EmbeddingMatchEvidence;
use oneiron_store::embedding_vocabulary::InputKind;
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
    #[serde(default)]
    pub lane: VectorSearchLane,
    /// The caller's retrieval filter (FIX 3977): bound before candidate
    /// generation, so it narrows every channel, seed and terminal read.
    #[serde(default)]
    pub filter: Option<oneiron_contracts::gate::ReadFilterInput>,
}

impl VectorSearchRequest {
    pub fn validate(&self) -> MemoryResult<()> {
        caps::check_limit_nonzero(self.limit)?;
        caps::check_dimensions(self.query.len())?;
        if let Some(error) = oneiron_base::error::Error::invalid_vector_component(&self.query) {
            return Err(error.into());
        }
        if self.space.is_none() && (self.query_kind.is_some() || !self.kinds.is_empty()) {
            return Err(MemoryError::bad_request(
                "query_kind and kinds name a declared space; set space too",
            ));
        }
        if self.space.is_some() && self.lane == VectorSearchLane::VoiceHot {
            return Err(MemoryError::bad_request(
                "voice_hot prefix scoring is a text-index lane; omit space",
            ));
        }
        Ok(())
    }
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
