//! Moved from `crates/oneiron/src/ingest/docs_import.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DocsImportCeiling {
    pub max_pages: usize,
    pub max_bytes: usize,
    pub allow_derivations: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocsDerivationEnvelope {
    pub source_ref: String,
    pub source_hash: String,
    pub producer: String,
    pub source: String,
    pub derived_kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocsImportReceipt {
    pub approval_digest: String,
    pub asset_refs: Vec<String>,
    pub chunk_refs: Vec<String>,
    pub summary_refs: Vec<String>,
    pub annotation_refs: Vec<String>,
    pub fingerprints: Vec<(String, super::BlobBirthDecision)>,
    /// The first page this call did not write when its deadline passed;
    /// `None` once every page is written and the consent is spent. The refs
    /// above name what this call wrote.
    pub resume_page: Option<usize>,
}
