//! Core half of `batch::secret_scan::mask::text_spans`: its store-layer items live in `oneiron_store::batch::secret_scan::mask::text_spans` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::batch::secret_scan::mask::text_spans::*;

use super::super::shapes;
use super::super::{REASON_MNEMONIC, REASON_PRIVATE_KEY, provider_token_spans};
use super::{REASON_BLOCKLIST, REASON_SENSITIVE_ENV};
use std::ops::Range;

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
