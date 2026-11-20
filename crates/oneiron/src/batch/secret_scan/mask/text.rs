//! A text's mask on write (OF-560): each span the door's text rules place,
//! and each value custody already holds, replaced by its handle. A tracked
//! pass also keeps where each handle went (FIX 6144), so a writer that
//! indexes into the text (a replay capsule's exposure spans) moves its
//! bounds by the replacements the pass made, never by a guess.

use std::collections::{BTreeSet, HashMap};
use std::ops::Range;

use super::side_row::bare_handle;
use super::text_log::TextSpans;
use super::{HANDLE_OPEN, Masker, STAND_IN, secret_spans};
use crate::error::Result;
use crate::store::known_value_index::{KnownSpan, KnownValues};

/// Each text a tracked pass masked, by the BLAKE3 of the text as given:
/// every replacement it made there, in order, as the span it replaced and
/// the span its handle took in the masked text.
pub(crate) type TextReplacements = HashMap<[u8; 32], Vec<(Range<usize>, Range<usize>)>>;

/// What one span of a text is: a value custody holds, by its handle, or a
/// shape the door's text rules place, by its reason.
enum TextHit {
    Known(String),
    Shape(&'static str),
}

impl Masker {
    /// `text` with each secret span the door's text rules place replaced by
    /// its handle. `None` when it holds none. A tracked pass keeps where
    /// each handle went.
    pub(super) fn mask_text(&mut self, text: &str) -> Result<Option<String>> {
        let spans = self.text_spans(text);
        let known = spans.known;
        let mut hits: Vec<(Range<usize>, TextHit)> = spans
            .shapes
            .into_iter()
            .filter(|(span, _)| {
                !known
                    .iter()
                    .any(|(held, _)| held.start < span.end && span.start < held.end)
            })
            .map(|(span, reason)| (span, TextHit::Shape(reason)))
            .collect();
        hits.extend(
            known
                .into_iter()
                .map(|(span, handle)| (span, TextHit::Known(handle))),
        );
        if hits.is_empty() {
            return Ok(None);
        }
        hits.sort_by_key(|(span, _)| span.start);
        // A span that cuts a char boundary is widened to it, so no slice
        // below panics (FIX 8648).
        hits = hits
            .into_iter()
            .map(|(span, hit)| (widen(text, span), hit))
            .collect();
        hits.sort_by_key(|(span, _)| span.start);
        let mut out = String::with_capacity(text.len());
        let mut from = 0;
        let mut placed = false;
        let mut replaced = Vec::new();
        for (span, hit) in hits {
            // A widened span may open inside the last one: it stays as
            // written, so no slice runs backwards (FIX 8648).
            if span.start < from {
                continue;
            }
            let handle = match hit {
                TextHit::Known(handle) => {
                    self.placed_known = true;
                    handle
                }
                TextHit::Shape(reason) => {
                    if self.is_kept(text[span.clone()].as_bytes()) {
                        continue;
                    }
                    self.handle(text[span.clone()].as_bytes(), reason)?
                }
            };
            placed = true;
            out.push_str(&text[from..span.start]);
            let at = out.len();
            out.push_str(HANDLE_OPEN);
            out.push_str(&handle);
            out.push(']');
            from = span.end;
            replaced.push((span, at..out.len()));
        }
        if !placed {
            return Ok(None);
        }
        out.push_str(&text[from..]);
        if let Some(traced) = &mut self.traced {
            traced.insert(*blake3::hash(text.as_bytes()).as_bytes(), replaced);
        }
        Ok(Some(out))
    }

    /// Each non-kept known value in `text` outside the handles it holds
    /// that name a record, with its record's handle, and each span the
    /// door's text rules place: taken from the plan's log when this pass
    /// reads the text the plan read at this place (speed), else found and,
    /// by a plan, logged.
    fn text_spans(&mut self, text: &str) -> TextSpans {
        if let Some(spans) = self.text_log.take(text.as_bytes()) {
            return spans;
        }
        // A read for given records knows their handles alone (blind review
        // round 1 of #9528): a handle custody took after those records were
        // named stays text, as it was when they were named.
        let names = |handle: &str| match &self.records {
            Some(records) => records.contains(handle),
            None => self
                .known
                .as_ref()
                .is_some_and(|known| known.holds_handle(handle)),
        };
        let known = match &self.known {
            Some(known) => known_outside_handles(
                known,
                self.records.as_ref(),
                self.records_longest,
                text,
                |value| self.is_kept(value),
                |handle| names(handle) || self.placed_handle(handle),
            ),
            None => Vec::new(),
        };
        // The switch is off: no shape span is discovered (FIX 8644). A text
        // the door's scan read clean holds none.
        let shapes = if self.known_only || self.shapes_read {
            Vec::new()
        } else {
            secret_spans(text)
        };
        let spans = TextSpans { known, shapes };
        self.text_log.record(text.as_bytes(), &spans);
        spans
    }

    /// Whether `handle` is one this pass, or a pass of this write before it
    /// (the seed it shares), gave a value: the record it names was minted in
    /// this write, so values custody read before the mint may not hold it.
    fn placed_handle(&self, handle: &str) -> bool {
        handle != STAND_IN && self.handles.0.values().any(|placed| placed == handle)
    }
}

/// Each non-kept known value in `text`, with its record's handle, read in
/// each stretch between the handles `text` holds that name a record,
/// `names` says which, and never across or inside one (FIX
/// REPLAY-COMPARE-KNOWN-OTHER-CALLERS): such a handle names its record and
/// holds no value, so a known value that spells part of it (`secret`), or
/// that a handle's closing bracket opens (`]!~!`), is not in the text, and
/// the value that follows the handle is still found. A mask of a row it
/// already masked so places nothing new (an authored row admitted, then
/// put), and a stored row is read as its write read it. Text spelled as a
/// handle that names no record is read like any other text (blind review
/// round 2 of #9503): a known value spelled `[secret sc99]` takes its own
/// record's handle and is never kept as written. With `records`, only those
/// records' values are read, as far as `longest` ([`known_spans`]), and
/// `names` takes only their handles.
fn known_outside_handles(
    known: &KnownValues,
    records: Option<&BTreeSet<String>>,
    longest: Option<usize>,
    text: &str,
    keep: impl Fn(&[u8]) -> bool,
    names: impl Fn(&str) -> bool,
) -> Vec<(Range<usize>, String)> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut from = 0;
    let end = text.len()..text.len();
    let handles = handle_slots(text)
        .into_iter()
        .filter(|(_, handle)| names(*handle))
        .map(|(span, _)| span);
    for handle in handles.chain(std::iter::once(end)) {
        let stretch = &bytes[from..handle.start];
        found.extend(
            known_spans(known, records, longest, stretch, &keep)
                .into_iter()
                .map(|hit| {
                    (
                        from + hit.span.start..from + hit.span.end,
                        hit.handle.to_owned(),
                    )
                }),
        );
        from = handle.end;
    }
    found
}

/// Each known value in `data` past those `keep` exempts: every value
/// `known` holds, or with `records`, only the values those records hold,
/// every other value out before the longest at a place is chosen (FIX
/// RECEIPT-RECORDS-CALL-HELD-INPUT), and with `longest` too, only those at
/// most that many bytes long.
pub(super) fn known_spans<'k>(
    known: &'k KnownValues,
    records: Option<&BTreeSet<String>>,
    longest: Option<usize>,
    data: &[u8],
    keep: impl Fn(&[u8]) -> bool,
) -> Vec<KnownSpan<'k>> {
    match records {
        Some(records) => {
            known.spans_held_by(data, keep, |handle| records.contains(handle), longest)
        }
        None => known.spans_except(data, keep),
    }
}

/// Each handle `text` holds, as its bare `sc12`, in order.
pub(super) fn handles_in(text: &str) -> impl Iterator<Item = &str> {
    handle_slots(text).into_iter().map(|(_, handle)| handle)
}

/// Each handle `text` holds, in order: its span, and its bare `sc12`.
pub(super) fn handle_slots(text: &str) -> Vec<(Range<usize>, &str)> {
    handle_spans(text)
        .into_iter()
        .map(|span| {
            let held = &text[span.clone()];
            let handle = held
                .strip_prefix(HANDLE_OPEN)
                .and_then(|body| body.strip_suffix(']'))
                .unwrap_or(held);
            (span, handle)
        })
        .collect()
}

/// The spans of `text` a mask on write placed a handle in, in order: each
/// `[secret sc12]`, and the whole text when it is a bare `sc12`.
fn handle_spans(text: &str) -> Vec<Range<usize>> {
    if bare_handle(text) {
        return vec![0..text.len()];
    }
    let mut spans = Vec::new();
    let mut at = 0;
    while let Some(open) = text[at..].find(HANDLE_OPEN).map(|found| at + found) {
        let body = open + HANDLE_OPEN.len();
        at = match text[body..].find(']') {
            Some(len) if bare_handle(&text[body..body + len]) => {
                spans.push(open..body + len + 1);
                body + len + 1
            }
            _ => body,
        };
    }
    spans
}

/// `span` widened to UTF-8 char boundaries: its start down, its end up
/// (FIX 8648).
fn widen(text: &str, span: Range<usize>) -> Range<usize> {
    let mut start = span.start.min(text.len());
    while start > 0 && !text.is_char_boundary(start) {
        start -= 1;
    }
    let mut end = span.end.min(text.len());
    while end < text.len() && !text.is_char_boundary(end) {
        end += 1;
    }
    start..end
}
