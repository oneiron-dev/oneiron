//! The spans the door's text rules place (OF-560): in a text, in each run of
//! text in a file's bytes, and at each place a value's bytes sit; merged
//! where they meet.

use std::ops::Range;

/// Every place `value`'s bytes sit in `data`, in order, overlapping ones
/// included. Only a place that opens with `value`'s first byte is compared
/// whole (speed); an empty value sits nowhere.
pub fn occurrences<'a>(data: &'a [u8], value: &'a [u8]) -> impl Iterator<Item = Range<usize>> + 'a {
    let first = value.first().copied();
    let mut from = 0;
    std::iter::from_fn(move || {
        let first = first?;
        loop {
            let rest = data.get(from..).filter(|rest| rest.len() >= value.len())?;
            let at = from + rest.iter().position(|&byte| byte == first)?;
            from = at + 1;
            if data.get(at..at + value.len()) == Some(value) {
                return Some(at..at + value.len());
            }
        }
    })
}

/// `spans` in order, merged where they meet; the first span's reason names
/// a merged one.
pub fn merged(mut spans: Vec<(Range<usize>, &'static str)>) -> Vec<(Range<usize>, &'static str)> {
    spans.retain(|(span, _)| !span.is_empty());
    spans.sort_by_key(|(span, _)| (span.start, std::cmp::Reverse(span.end)));
    let mut merged: Vec<(Range<usize>, &'static str)> = Vec::with_capacity(spans.len());
    for (span, reason) in spans {
        match merged.last_mut() {
            Some((last, _)) if span.start <= last.end => last.end = last.end.max(span.end),
            _ => merged.push((span, reason)),
        }
    }
    merged
}
