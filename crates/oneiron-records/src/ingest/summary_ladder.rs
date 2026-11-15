//! Moved from `crates/oneiron/src/ingest/summary_ladder.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DocsSummaryHit {
    pub reference: String,
    pub entity_type: u8,
    pub rank_score: f32,
    /// Only summary hits contain text. Chunks require an explicit expand call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocsExpansionLevel {
    Summary,
    Span,
    Section,
    FullText,
    RawAsset,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DocsExpansion {
    pub level: DocsExpansionLevel,
    pub text: String,
    /// The next rung is offered as a ref, not automatically read.
    pub next_ref: Option<String>,
    /// Only the final rung carries source metadata; full text is never a search hit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset: Option<serde_json::Value>,
}
