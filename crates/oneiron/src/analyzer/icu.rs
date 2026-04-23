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
//! segment. Non-word-like segments (whitespace, punctuation) are skipped.

use icu_segmenter::WordSegmenter;
use icu_segmenter::WordSegmenterBorrowed;
use icu_segmenter::options::WordBreakInvariantOptions;

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
        if segment_type.is_word_like() {
            let slice = &text[prev_offset..end];
            let start = offset_base + prev_offset as u32;
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
    fn empty_input_returns_position_base() {
        let mut out = Vec::new();
        let next = analyze("", 0, 9, &mut out);
        assert_eq!(next, 9);
        assert!(out.is_empty());
    }

    #[test]
    fn thai_input_produces_word_tokens() {
        let mut out = Vec::new();
        analyze("ไปโรงเรียน", 0, 0, &mut out);
        let terms = surface_terms(&out);
        // ICU4X segments Thai via its dictionary/LSTM. We don't pin exact
        // boundaries (they can shift between ICU versions); only assert the
        // segmenter returned at least one word-like segment.
        assert!(!terms.is_empty());
    }

    #[test]
    fn offsets_slice_into_original_text() {
        let text = "hello world";
        let mut out = Vec::new();
        analyze(text, 0, 0, &mut out);
        // Guard against a regression where the loop emits the wrong
        // segment but the case-fold identity still satisfies the
        // per-token equality check: require both words to land as
        // distinct tokens.
        assert!(
            out.len() >= 2,
            "expected at least 2 tokens for `hello world`, got {}: {:?}",
            out.len(),
            surface_terms(&out),
        );
        for tok in &out {
            let slice = &text[tok.byte_start as usize..tok.byte_end as usize];
            assert!(!slice.is_empty());
            assert!(slice.eq_ignore_ascii_case(&tok.term));
        }
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

    #[test]
    fn pure_numeric_emits_number_token() {
        let text = "123";
        let mut out = Vec::new();
        analyze(text, 0, 0, &mut out);
        let terms = surface_terms(&out);
        assert_eq!(terms, vec!["123"]);
        let tok = out
            .iter()
            .find(|t| t.channel == AnalyzerChannel::Surface)
            .expect("numeric segment must emit a token");
        assert_eq!((tok.byte_start, tok.byte_end), (0, 3));
    }

    #[test]
    fn thai_first_segment_is_emitted() {
        let text = "ไปโรงเรียน";
        let mut out = Vec::new();
        analyze(text, 0, 0, &mut out);
        // Regression guard: the off-by-one bug in the word-type loop
        // dropped the first segment of every ICU-dispatched input
        // because `prev_type` for the initial `(0, None)` boundary was
        // never `word_like`. Require at least one token to start at
        // byte 0 to prove the first segment survives.
        assert!(
            out.iter().any(|t| t.byte_start == 0),
            "expected a token starting at byte 0, got: {:?}",
            surface_terms(&out),
        );
    }

    #[test]
    fn offset_base_shifts_absolute_offsets() {
        let mut out = Vec::new();
        analyze("hi there", 100, 0, &mut out);
        for tok in &out {
            assert!(tok.byte_start >= 100);
            assert!(tok.byte_end >= tok.byte_start);
        }
    }

    #[test]
    fn punctuation_only_produces_no_tokens() {
        let mut out = Vec::new();
        analyze("   ...!!!", 0, 0, &mut out);
        assert!(surface_terms(&out).is_empty());
    }
}
