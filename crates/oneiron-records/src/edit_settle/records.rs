//! Moved from `crates/oneiron/src/edit_settle/records.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// Selected Office author and the separate identities behind a review comment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PptxReviewIdentity {
    pub thread_id: EntityId,
    pub asked_by: EntityId,
    pub answered_by: EntityId,
    pub export_author_guid: String,
    pub export_author_name: String,
}
