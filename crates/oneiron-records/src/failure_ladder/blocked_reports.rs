//! Moved from `crates/oneiron/src/failure_ladder/blocked_reports.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Reference-only projection of ONE-1686's durable `report_blocked` receipt.
///
/// The category/detail stay owned by and decoded through ONE-1686. This lane
/// deliberately does not duplicate that four-category enum or its receipt
/// codec, so the ref stays opaque here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedReportRef {
    /// Lowercase-hex EntityId spelling.
    pub receipt_ref: String,
}
