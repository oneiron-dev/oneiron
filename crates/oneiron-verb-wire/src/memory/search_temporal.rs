//! Moved from `crates/oneiron/src/memory/search_temporal.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::pipeline::temporal_report::TemporalSearchReport;
use serde::Deserialize;
use serde::Serialize;

/// One admitted result, with dates from the same source revision the run pinned.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TemporalSearchHit {
    pub entity_ref: String,
    pub source_revision_ref: Option<String>,
    pub score: f32,
    pub occurred_start: u64,
    pub occurred_end: u64,
    pub learned_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TemporalSearchResult {
    pub hits: Vec<TemporalSearchHit>,
    /// None when authority prevented the temporal channel from running.
    pub widening: Option<TemporalSearchReport>,
}
