//! Moved from `crates/oneiron/src/memory/search_hybrid.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::retrieval_telemetry::RetrievalBlendWeights;
use oneiron_contracts::retrieval_telemetry::RetrievalScoreComponent;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HybridPprQuery {
    /// Short record refs or 32-hex entity ids, admitted by the caller's lane.
    pub seeds: Vec<String>,
    pub depth: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HybridTemporalQuery {
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HybridRankReplay {
    /// Unix seconds for temporal interpretation and time-dependent scoring.
    pub now: u64,
    pub blend_weights: RetrievalBlendWeights,
}

/// Evidence for one admitted result, available even when telemetry is off.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HybridSearchHit {
    pub entity_ref: String,
    pub source_revision_ref: Option<String>,
    pub score: f32,
    pub access_factor: Option<f32>,
    pub components: Vec<RetrievalScoreComponent>,
}
