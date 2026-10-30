//! The spans the door's text rules place (OF-560): in a text, in each run of
//! text in a file's bytes, and at each place a value's bytes sit; merged
//! where they meet.

use std::ops::Range;

use super::super::shapes;
use super::super::{REASON_MNEMONIC, REASON_PRIVATE_KEY, provider_token_spans};
use super::{REASON_BLOCKLIST, REASON_SENSITIVE_ENV};

/// The spans of `text` the write door's text rules place, merged where they
/// meet, in order: a private-key block, a blocklist entry, a provider key
/// token, an assigned value under a credential name, and a recovery phrase.
pub(super) fn secret_spans(text: &str) -> Vec<(Range<usize>, &'static str)> {
    let spans: Vec<(Range<usize>, &'static str)> = shapes::private_key_block_spans(text)
        .into_iter()
        .map(|span| (span, REASON_PRIVATE_KEY))
        .chain(
            shapes::blocklist_spans(text)
                .into_iter()
                .map(|span| (span, REASON_BLOCKLIST)),
        )
        .chain(provider_token_spans(text))
        .chain(
            shapes::assignment_spans(text)
                .into_iter()
                .map(|span| (span, REASON_SENSITIVE_ENV)),
        )
        // A recovery phrase takes one span per phrase (FIX 1099).
        .chain(
            shapes::mnemonic_spans(text)
                .into_iter()
                .map(|span| (span, REASON_MNEMONIC)),
        )
        .collect();
    merged(spans)
}

/// The spans the door's text rules place in each run of text in a file, at
/// their offsets in its bytes.
pub(super) fn file_spans(data: &[u8]) -> Vec<(Range<usize>, &'static str)> {
    let mut spans = Vec::new();
    let mut at = 0;
    while let Some(rest) = data.get(at..).filter(|rest| !rest.is_empty()) {
        let (valid, skip) = match std::str::from_utf8(rest) {
            Ok(_) => (rest.len(), 0),
            Err(error) => (
                error.valid_up_to(),
                error
                    .error_len()
                    .unwrap_or(rest.len() - error.valid_up_to()),
            ),
        };
        if let Some(text) = rest
            .get(..valid)
            .and_then(|run| std::str::from_utf8(run).ok())
        {
            spans.extend(
                secret_spans(text)
                    .into_iter()
                    .map(|(span, reason)| (span.start + at..span.end + at, reason)),
            );
        }
        at += valid + skip;
    }
    spans
}

/// Every place `value`'s bytes sit in `data`.
pub(super) fn occurrences<'a>(
    data: &'a [u8],
    value: &'a [u8],
) -> impl Iterator<Item = Range<usize>> + 'a {
    data.windows(value.len().max(1))
        .enumerate()
        .filter(move |(_, window)| !value.is_empty() && *window == value)
        .map(move |(at, _)| at..at + value.len())
}

/// `spans` in order, merged where they meet; the first span's reason names
/// a merged one.
pub(super) fn merged(
    mut spans: Vec<(Range<usize>, &'static str)>,
) -> Vec<(Range<usize>, &'static str)> {
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
