//! Moved from `crates/oneiron/src/merge_queue/check_store.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::merge_queue::check_inputs::QueueCheckHold;
use crate::merge_queue::check_inputs::QueueCheckNeed;
use serde::Deserialize;
use serde::Serialize;

/// Where a checked initialization stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueueCheckInitStage {
    /// Approved and frozen; the baseline checks have not passed.
    Requested,
    /// Both baseline phases passed and the contract baseline is recorded;
    /// the queue is not initialized yet. A retry only attaches.
    Checked { baseline_id: String },
    /// The queue was initialized at the baseline.
    Initialized { baseline_id: String },
}

/// Where a work row stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueueCheckStatus {
    Queued,
    Running,
    /// The work is kept; nothing went green.
    NeedsConfiguration(QueueCheckNeed),
    /// No verdict; the work and its exhaust are kept.
    Held(QueueCheckHold),
    /// The work ran to a verdict, or for an init to its pointers.
    Completed {
        passed: bool,
    },
    /// The path this check fills already held a verdict when it ran.
    Settled {
        verdict_ref: String,
    },
}

/// The attempt lease one running generation holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueCheckLease {
    pub owner: String,
    /// The attempt's own lease generation fence.
    pub attempt_count: u32,
}
