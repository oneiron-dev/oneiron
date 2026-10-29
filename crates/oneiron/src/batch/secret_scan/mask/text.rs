//! A text's mask on write (OF-560): each span the door's text rules place,
//! and each value custody already holds, replaced by its handle. A tracked
//! pass also keeps where each handle went (FIX 6144), so a writer that
//! indexes into the text (a replay capsule's exposure spans) moves its
//! bounds by the replacements the pass made, never by a guess.

use std::collections::HashMap;
use std::ops::Range;

use super::{HANDLE_OPEN, Masker, secret_spans};
use crate::error::Result;

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
        let known = self.known_spans(text);
        // The switch is off: no shape span is discovered (FIX 8644).
        let mut hits: Vec<(Range<usize>, TextHit)> = Vec::new();
        if !self.known_only {
            hits.extend(
                secret_spans(text)
                    .into_iter()
                    .filter(|(span, _)| {
                        !known
                            .iter()
                            .any(|(held, _)| held.start < span.end && span.start < held.end)
                    })
                    .map(|(span, reason)| (span, TextHit::Shape(reason))),
            );
        }
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

    /// Each value custody holds in `text`, with its record's handle, but a
    /// value the owner ruled no secret in the record the pass reads: that
    /// ruling wins over the known-value sweep.
    fn known_spans(&self, text: &str) -> Vec<(Range<usize>, String)> {
        let Some(known) = &self.known else {
            return Vec::new();
        };
        known
            .spans(text.as_bytes())
            .into_iter()
            .filter(|hit| !self.is_kept(&text.as_bytes()[hit.span.clone()]))
            .map(|hit| (hit.span, hit.handle.to_owned()))
            .collect()
    }
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
