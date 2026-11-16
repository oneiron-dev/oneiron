//! Moved from `crates/oneiron/src/receipt/family.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Query for the EF-055 pending tray lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingTrayQuery {
    pub now: u64,
    pub limit: usize,
}

impl PendingTrayQuery {
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            now: oneiron_base::unix_seconds_now(),
            limit,
        }
    }

    #[must_use]
    pub const fn at(now: u64, limit: usize) -> Self {
        Self { now, limit }
    }
}
