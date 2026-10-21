//! Exact-quote evidence (FIX 7506, ARCH-0026 row 1). A reply cites a source
//! by its call label and a short run of words copied from it; the engine
//! finds those words in the text the call showed and binds the byte range
//! itself. A quote is never repaired, never matched at its first occurrence
//! and never widened to its whole source: one occurrence binds, two or more
//! are ambiguous, none is not found. Exact bytes are tried first. When they
//! occur nowhere, one fallback folds each run of Unicode whitespace to one
//! space on both sides (no case, punctuation or Unicode normalization) and
//! maps the match back to the source's own bytes, under the same rule. A
//! quote spanning two sources matches neither: each source is searched
//! alone. "Short" is the prompt's advice, never a cap.

use crate::EntityId;
use crate::dreamer_consolidation::call_labels::SourceShown;

/// Whether a quote found nowhere byte for byte is looked for once more with
/// each whitespace run folded to one space.
pub(in crate::dreamer_consolidation) const QUOTE_WHITESPACE_FOLD: bool = true;

/// What one quote binds to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::dreamer_consolidation) enum QuoteBinding {
    /// The one place in `source`'s shown text the quote names, as UTF-8
    /// byte offsets on character boundaries.
    Bound {
        source: EntityId,
        start: usize,
        end: usize,
    },
    /// The quote is empty.
    EmptyQuote,
    /// The label names no source its call showed.
    UnknownSourceLabel,
    /// The source's shown text holds the quote nowhere.
    QuoteNotFound,
    /// The source's shown text holds the quote more than once.
    QuoteAmbiguous,
}

impl QuoteBinding {
    /// The result's name, as a refusal or a skip carries it.
    pub(in crate::dreamer_consolidation) const fn name(self) -> &'static str {
        match self {
            Self::Bound { .. } => "evidence quote bound (Bound)",
            Self::EmptyQuote => "evidence quote is empty (EmptyQuote)",
            Self::UnknownSourceLabel => {
                "evidence names a label its call did not show (UnknownSourceLabel)"
            }
            Self::QuoteNotFound => "evidence quote is not in its source (QuoteNotFound)",
            Self::QuoteAmbiguous => {
                "evidence quote occurs more than once in its source (QuoteAmbiguous)"
            }
        }
    }
}

/// Binds `quote` against what its call showed of `source`; `None` for a
/// label that names no source the call showed.
pub(in crate::dreamer_consolidation) fn bind_quote(
    source: Option<(EntityId, SourceShown<'_>)>,
    quote: &str,
) -> QuoteBinding {
    if quote.is_empty() {
        return QuoteBinding::EmptyQuote;
    }
    let Some((source, shown)) = source else {
        return QuoteBinding::UnknownSourceLabel;
    };
    let text = shown.text.unwrap_or_default();
    let found = match exact(text, quote) {
        Found::Absent if QUOTE_WHITESPACE_FOLD => folded(text, quote),
        found => found,
    };
    match found {
        Found::One(start, end) => QuoteBinding::Bound { source, start, end },
        Found::Many => QuoteBinding::QuoteAmbiguous,
        Found::Absent => QuoteBinding::QuoteNotFound,
    }
}

/// How often a quote occurs.
enum Found {
    Absent,
    /// Once, at these byte offsets.
    One(usize, usize),
    Many,
}

/// Every occurrence of the nonempty `quote` in `text`, overlapping ones
/// counted too.
fn exact(text: &str, quote: &str) -> Found {
    let mut found = Found::Absent;
    let mut from = 0;
    while let Some(at) = text.get(from..).and_then(|rest| rest.find(quote)) {
        let start = from + at;
        if matches!(found, Found::One(..)) {
            return Found::Many;
        }
        found = Found::One(start, start + quote.len());
        from = start + text[start..].chars().next().map_or(1, char::len_utf8);
    }
    found
}

/// [`exact`] over `text` and `quote` with each run of Unicode whitespace
/// folded to one space, its match mapped back to `text`'s own bytes.
fn folded(text: &str, quote: &str) -> Found {
    let (folded_text, spans) = fold(text);
    let (folded_quote, _) = fold(quote);
    match exact(&folded_text, &folded_quote) {
        Found::One(start, end) => {
            let first = spans.get(spans.partition_point(|span| span.0 < start));
            let last = spans
                .partition_point(|span| span.0 < end)
                .checked_sub(1)
                .and_then(|at| spans.get(at));
            match (first, last) {
                (Some(first), Some(last)) => Found::One(first.1, last.2),
                _ => Found::Absent,
            }
        }
        other => other,
    }
}

/// `text` with each run of whitespace folded to one space, and for each
/// folded character its byte offset in the folded text and the byte range
/// of `text` it stands for.
fn fold(text: &str) -> (String, Vec<(usize, usize, usize)>) {
    let mut folded = String::with_capacity(text.len());
    let mut spans: Vec<(usize, usize, usize)> = Vec::new();
    let mut in_space = false;
    for (at, c) in text.char_indices() {
        let end = at + c.len_utf8();
        if c.is_whitespace() {
            if in_space {
                if let Some(last) = spans.last_mut() {
                    last.2 = end;
                }
                continue;
            }
            in_space = true;
            spans.push((folded.len(), at, end));
            folded.push(' ');
        } else {
            in_space = false;
            spans.push((folded.len(), at, end));
            folded.push(c);
        }
    }
    (folded, spans)
}
