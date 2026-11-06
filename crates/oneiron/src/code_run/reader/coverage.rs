//! Byte-range arithmetic of reader coverage (ARCH-0079 #reader-forks): the
//! ranges a fold receipt counts as read, merged, and what of a source they
//! leave.

/// `ranges` sorted and merged where they touch or overlap.
pub(crate) fn merge_ranges(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
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

/// What of `whole` the merged `covered` ranges leave.
pub(crate) fn subtract_ranges(whole: (u64, u64), covered: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut left = Vec::new();
    let mut at = whole.0;
    for &(start, end) in covered {
        if end <= at || start >= whole.1 {
            continue;
        }
        if start > at {
            left.push((at, start.min(whole.1)));
        }
        at = at.max(end);
    }
    if at < whole.1 {
        left.push((at, whole.1));
    }
    left
}
