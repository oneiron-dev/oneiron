//! Moved from `crates/oneiron/src/ingest/docs.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_store::document_segments::DOCS_SEGMENT_MAX_BYTES;
pub use oneiron_store::document_segments::DocsSegment;
pub use oneiron_store::document_segments::docs_semantic_segments;
use serde::Deserialize;
use serde::Serialize;

pub const DOCS_EXPORT_SOURCE_ID: &str = "docs-export";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocsPage {
    pub page_id: String,
    pub path: String,
    pub text: String,
}
