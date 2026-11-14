//! Moved from `crates/oneiron/src/code_run/reader/coverage.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Each of `ranges` cut to `within`. A range that falls outside it becomes
/// empty, and [`merge_ranges`] drops it.
pub fn clip_ranges(ranges: &[(u64, u64)], within: (u64, u64)) -> impl Iterator<Item = (u64, u64)> {
    ranges
        .iter()
        .map(move |&(start, end)| (start.max(within.0), end.min(within.1)))
}

/// `ranges` sorted and merged where they touch or overlap.
pub fn merge_ranges(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.retain(|(start, end)| start < end);
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}
