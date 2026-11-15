//! Moved from `crates/oneiron/src/failure_signals/status.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Serialize;

/// Stored work, not a promise that each row is currently export-eligible.
/// A carried batch's frozen shares are already in these queues and are not
/// added a second time. An ambiguous send removes its counts but keeps its
/// code-fix records until an acknowledged delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FailureSignalWaiting {
    pub count_rows: u64,
    pub signal_count: u64,
    pub code_fix_records: u64,
}

/// The newest durable material-result receipt by its recorded timestamp,
/// then receipt id to make equal timestamps deterministic. Replays keep
/// their first material observation; this is not current connectivity or a
/// record of an idle pass or a failure before a receipt could be committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FailureSignalBatchReceipt {
    pub occurred_at: u64,
    pub outcome: String,
}

/// One read-only store snapshot. Counts remain visible when exports are off
/// until the sender's ordinary reconciliation removes them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FailureSignalDeliveryStatus {
    pub exports_enabled: bool,
    pub waiting: FailureSignalWaiting,
    pub last_batch_receipt: Option<FailureSignalBatchReceipt>,
}
