//! Moved from `crates/oneiron/src/ingest/docs_deep/review.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::claim::ClaimApprovalStatus;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

/// One derived claim as it was written and as the owner reviews it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocsDeepReviewClaim {
    pub claim_ref: String,
    /// The ASSET_TEXT chunk its quote was found in.
    pub chunk_ref: String,
    pub segment_hash: String,
    pub source_record_id: String,
    pub predicate: String,
    pub value: Value,
    /// When it was written; its occurred window is this instant.
    pub learned_at: u64,
}

/// The owner's one review of every claim derived from a source revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocsDeepReview {
    /// Each derived claim, in `claim_refs` order.
    pub claims: Vec<DocsDeepReviewClaim>,
    /// `Proposed` until the owner approves or declines the exact batch, or a
    /// standing grant approves every batch as it is written.
    pub decision: ClaimApprovalStatus,
    /// The standing grant that approved the claims, when one did.
    pub standing_grant_ref: Option<String>,
}

impl DocsDeepReview {
    pub const fn proposed() -> Self {
        Self {
            claims: Vec::new(),
            decision: ClaimApprovalStatus::Proposed,
            standing_grant_ref: None,
        }
    }
}
