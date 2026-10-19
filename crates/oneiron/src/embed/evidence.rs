//! Raw match evidence stays keyed by the space and input kind that produced it.
use super::InputKind;
use serde::{Deserialize, Serialize};

/// A cosine is meaningful only in this exact model@revision@where space.
/// These are the floors the retrieval run actually used, before fusion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EmbeddingMatchEvidence {
    pub space: String,
    pub embedding_kind: InputKind,
    pub query_kind: InputKind,
    pub score: f32,
    pub floor: f32,
    pub strong: f32,
    pub matched: bool,
}
