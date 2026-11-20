//! Moved from `crates/oneiron/src/note/tombstone_review.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// One proposed NOTE tombstone, for the owner to accept or decline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteTombstoneProposal {
    pub note: EntityId,
    /// The NOTE's kind, whose retention it outlived.
    pub kind: String,
    /// The kind's retention, in days.
    pub retention_days: u32,
    /// Unix seconds the NOTE was archived.
    pub archived_at: u64,
    /// The archive's request id. The proposal holds for this archive only:
    /// a NOTE restored and archived again is a new question.
    pub archive_request: Option<[u8; 16]>,
    /// Unix seconds the review proposed it.
    pub proposed_at: u64,
    /// Unix seconds the owner declined it, if they did.
    pub declined_at: Option<u64>,
}
