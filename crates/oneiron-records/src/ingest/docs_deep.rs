//! Moved from `crates/oneiron/src/ingest/docs_deep.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::ingest::docs_deep::review::DocsDeepReview;
pub use crate::ingest::docs_deep::review::DocsDeepReviewClaim;
use crate::ingest::docs_import::DocsDerivationEnvelope;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::time::Duration;
use std::time::Instant;

/// A source-grounded entity/fact proposed by the host's NER implementation.
/// The quote must occur verbatim in the source segment, never in a model-only summary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DocsDeepClaim {
    pub predicate: String,
    pub value: Value,
    pub quote: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DocsDeepTrigger {
    OnRead,
    Explicit,
    Dreamer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocsDeepReceipt {
    pub derivation: DocsDerivationEnvelope,
    pub trigger: DocsDeepTrigger,
    pub claim_refs: Vec<String>,
    /// The first source segment no batch has extracted yet when the call's
    /// deadline passed; `None` once every segment has been. The next call
    /// for this revision and extractor resumes there.
    pub resume_segment: Option<usize>,
    /// The derived claims as the owner reviews them: one exact batch.
    pub review: DocsDeepReview,
}
pub mod review;
