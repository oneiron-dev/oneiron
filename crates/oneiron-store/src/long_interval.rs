//! The occurrence span past which a stored record is a long interval.

/// An occurrence span longer than this (14 days) is a long interval: the
/// record also lands in the long-interval temporal index.
pub const LONG_INTERVAL_THRESHOLD_SECS: u64 = 14 * 86_400;
