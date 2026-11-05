//! Core half of `batch::secret_scan::mask::text`: its store-layer items live in `oneiron_store::batch::secret_scan::mask::text` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::batch::secret_scan::mask::text::*;

use super::text_log::TextSpans;
use super::{HANDLE_OPEN, Masker, secret_spans};
use crate::error::Result;
use std::collections::HashMap;
use std::ops::Range;

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

    /// Each non-kept known value in `text`, with its record's handle, and
    /// each span the door's text rules place: taken from the plan's log when
    /// this pass reads the text the plan read at this place (speed), else
    /// found and, by a plan, logged.
    fn text_spans(&mut self, text: &str) -> TextSpans {
        if let Some(spans) = self.text_log.take(text.as_bytes()) {
            return spans;
        }
        let known = match &self.known {
            Some(known) => known
                .spans_except(text.as_bytes(), |value| self.is_kept(value))
                .into_iter()
                .map(|hit| (hit.span, hit.handle.to_owned()))
                .collect(),
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
}
