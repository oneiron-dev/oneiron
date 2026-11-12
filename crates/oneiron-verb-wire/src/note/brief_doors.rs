//! Moved from `crates/oneiron/src/note/brief_doors.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// A source span for a load-bearing sentence in the authored markdown.
/// Offsets are half-open Unicode scalar indices in the source NOTE's live text.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BriefClaimCitation {
    /// The supporting CLAIM's 32-hex id.
    pub claim_ref: String,
    /// The quoted source NOTE's 32-hex id.
    pub document_ref: String,
    pub start: usize,
    pub end: usize,
}

/// Authored markdown, with supporting claim citations for each load-bearing
/// sentence. The engine captures the source frontier, cursors and quote hash;
/// no caller-supplied quote or rendered HTML is stored.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthorBriefRequest {
    pub markdown: String,
    pub citations: Vec<BriefClaimCitation>,
}
