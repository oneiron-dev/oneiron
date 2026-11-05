//! A text's mask on write (OF-560): each span the door's text rules place,
//! and each value custody already holds, replaced by its handle. A tracked
//! pass also keeps where each handle went (FIX 6144), so a writer that
//! indexes into the text (a replay capsule's exposure spans) moves its
//! bounds by the replacements the pass made, never by a guess.

use std::collections::HashMap;
use std::ops::Range;

use crate::batch::secret_scan::mask::text_log::TextSpans;
use oneiron_base::error::Result;

/// Each text a tracked pass masked, by the BLAKE3 of the text as given:
/// every replacement it made there, in order, as the span it replaced and
/// the span its handle took in the masked text.
pub type TextReplacements = HashMap<[u8; 32], Vec<(Range<usize>, Range<usize>)>>;

/// What one span of a text is: a value custody holds, by its handle, or a
/// shape the door's text rules place, by its reason.
pub enum TextHit {
    Known(String),
    Shape(&'static str),
}

/// `span` widened to UTF-8 char boundaries: its start down, its end up
/// (FIX 8648).
pub fn widen(text: &str, span: Range<usize>) -> Range<usize> {
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
