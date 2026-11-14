//! Moved from `crates/oneiron/src/housekeeping/schedule.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

/// The first retry after a failure. It doubles with each failure in a row, up
/// to the sweep's cadence and never past an hour.
pub const RETRY_AFTER_SECS: u64 = 60;

pub const RETRY_CAP_SECS: u64 = 60 * 60;

pub fn retry_after(failures: u32, every: u64) -> u64 {
    let doublings = failures.saturating_sub(1).min(16);
    RETRY_AFTER_SECS
        .saturating_mul(1 << doublings)
        .min(every)
        .min(RETRY_CAP_SECS)
}
