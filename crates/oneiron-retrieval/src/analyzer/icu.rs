//! ICU4X-backed word segmentation for scripts without a dedicated morph
//! analyzer in v1.
//!
//! Per plan §7: Thai, Lao, Khmer, Myanmar, and Vietnamese fall through to
//! ICU4X [`WordSegmenter::new_auto`]. `new_auto` uses the best available
//! compiled data for complex scripts, including Thai/Lao/Khmer/Myanmar
//! dictionary-driven break rules and LSTM where available (per the
//! icu_segmenter 2.2 docs).
//!
//! The wrapper returns `Surface` tokens with byte offsets into the caller's
//! original UTF-8 (`offset_base + local`), one position per word-like
//! segment. Non-word-like segments are scanned for emoji grapheme clusters
//! via `emoji::emit_emoji_graphemes` (ARCH-0031 dispatch row
//! "Emoji / unknown → Grapheme per token"); whatever remains (whitespace,
//! punctuation) is skipped.

use icu_segmenter::WordSegmenter;
use icu_segmenter::WordSegmenterBorrowed;
use icu_segmenter::options::WordBreakInvariantOptions;

use super::emoji;
use super::normalize;
use super::token::{AnalyzerChannel, Token, TokenKind};

/// Returns a fresh borrowed word segmenter. `new_auto` with `compiled_data`
/// returns a `WordSegmenterBorrowed<'static>` backed entirely by statically
/// linked ICU4X baked data, so there is no allocation or locale load cost.
fn segmenter() -> WordSegmenterBorrowed<'static> {
    WordSegmenter::new_auto(WordBreakInvariantOptions::default())
}

/// Analyze `text` using ICU4X word segmentation and append tokens to `out`.
///
/// Emits one `Surface` token per word-like segment. Offsets are absolute
/// byte positions in the caller's original UTF-8 (`offset_base + local`).
/// Surface terms are Unicode-casefolded via [`normalize::casefold`].
pub fn analyze(text: &str, offset_base: u32, position_base: u32, out: &mut Vec<Token>) -> u32 {
    if text.is_empty() {
        return position_base;
    }

    let seg = segmenter();
    let mut iter = seg.segment_str(text).iter_with_word_type();

    // `iter_with_word_type()` yields `(boundary, word_type_of_segment_ending_
    // at_boundary)` (icu_segmenter 2.x). The first yield is the start
    // boundary (0, None); each subsequent yield's `segment_type` describes
    // the segment `[prev_offset, end)` that we're about to consider — so
    // the word-likeness test must look at the *current* yield's type, not
    // the one we held over from the previous iteration.
    let Some((mut prev_offset, _)) = iter.next() else {
        return position_base;
    };
    let mut position = position_base;

    for (end, segment_type) in iter {
        let slice = &text[prev_offset..end];
        let start = offset_base + prev_offset as u32;
        if segment_type.is_word_like() {
            let end_abs = offset_base + end as u32;
            let folded = normalize::casefold(slice);
            out.push(Token::new(
                folded.as_ref(),
                start,
                end_abs,
                position,
                AnalyzerChannel::Surface,
                TokenKind::Word,
            ));
            position += 1;
        } else {
            // ARCH-0031 "Emoji / unknown → Grapheme per token": non-word
            // segments may carry emoji grapheme clusters — pictographics,
            // flags, keycaps (the word segmenter classifies emoji as
            // non-word, which used to drop them entirely). UAX #29 word
            // boundaries never split a grapheme cluster, so a ZWJ sequence
            // or flag pair is always wholly inside one segment here.
            position = emoji::emit_emoji_graphemes(slice, start, position, out);
        }
        prev_offset = end;
    }

    position
}

#[cfg(test)]
mod tests {
    use super::*;

    fn surface_terms(tokens: &[Token]) -> Vec<&str> {
        tokens
            .iter()
            .filter(|t| t.channel == AnalyzerChannel::Surface)
            .map(|t| t.term.as_ref())
            .collect()
    }

    #[test]
    fn ascii_words_emit_expected_tokens() {
        let text = "hello world";
        let mut out = Vec::new();
        analyze(text, 0, 0, &mut out);
        let terms = surface_terms(&out);
        assert_eq!(terms, vec!["hello", "world"]);
        let offsets: Vec<(u32, u32)> = out
            .iter()
            .filter(|t| t.channel == AnalyzerChannel::Surface)
            .map(|t| (t.byte_start, t.byte_end))
            .collect();
        assert_eq!(offsets, vec![(0, 5), (6, 11)]);
    }
}
