//! Moved from `crates/oneiron/src/booking/solver/counts.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

// -------------------------------------------------------------------------
// Confirmed-booking counts
// -------------------------------------------------------------------------

/// Confirmed bookings inside one visitor-local period.
///
/// The bucket's own UTC span is what a caller reads; which cap it is charged
/// against is decided from `window_start_utc`'s visitor-local day, so a table
/// built in one zone cannot be silently applied in another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookingCountBucket {
    pub window_start_utc: u64,
    /// Half-open `[window_start_utc, window_end_utc)`.
    pub window_end_utc: u64,
    pub confirmed: u16,
}

/// The typed cap input. Sparse by construction: a period with no bucket has no
/// confirmed bookings, which is zero, not unknown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookingCounts {
    pub daily: Vec<BookingCountBucket>,
    pub weekly: Vec<BookingCountBucket>,
}
