//! Vietnamese analyzer (ARCH-0031 dispatch row "Vietnamese → Whitespace +
//! NFC + lowercase", FIX 7780).
//!
//! Vietnamese writes one syllable per space-separated word, and its tone
//! marks are what a compatibility fold or a case fold must not reshape. A
//! run routed here is read from the caller's ORIGINAL bytes, ahead of the
//! global NFKC + casefold stage: each whitespace-separated word, its edge
//! punctuation trimmed, becomes one `Surface` term in NFC, lowercased. Emoji
//! between words emit as the Latin lane emits them.
//!
//! Offsets are byte positions into the passed-in slice plus `offset_base`.
//! The caller passes original-text bytes, so they need no remap.

use icu_normalizer::ComposingNormalizer;
use unicode_segmentation::UnicodeSegmentation;

use super::emoji;
use super::token::{AnalyzerChannel, Token, TokenKind};

/// Analyze one Vietnamese run and append its tokens to `out`. Returns the
/// next position that the caller should use after this run.
pub fn analyze(text: &str, offset_base: u32, position_base: u32, out: &mut Vec<Token>) -> u32 {
    let nfc = ComposingNormalizer::new_nfc();
    let mut position = position_base;
    let mut gap_start = 0usize;
    for (idx, word) in words(text) {
        if gap_start < idx {
            position = emoji::emit_emoji_graphemes(
                &text[gap_start..idx],
                offset_base + gap_start as u32,
                position,
                out,
            );
        }
        gap_start = idx + word.len();
        let start = offset_base + idx as u32;
        out.push(Token::new(
            nfc.normalize(word).to_lowercase(),
            start,
            start + word.len() as u32,
            position,
            AnalyzerChannel::Surface,
            TokenKind::Word,
        ));
        position += 1;
    }
    if gap_start < text.len() {
        position = emoji::emit_emoji_graphemes(
            &text[gap_start..],
            offset_base + gap_start as u32,
            position,
            out,
        );
    }
    position
}

/// Each whitespace-separated word of `text` beside its byte offset, with
/// [`trimmed`] edges; a word holding no letter or digit is no word.
fn words(text: &str) -> Vec<(usize, &str)> {
    let mut words = Vec::new();
    let mut start = None;
    for (idx, c) in text.char_indices().chain(std::iter::once((text.len(), ' '))) {
        match (start, c.is_whitespace()) {
            (None, false) => start = Some(idx),
            (Some(begin), true) => {
                if let Some((offset, word)) = trimmed(&text[begin..idx]) {
                    words.push((begin + offset, word));
                }
                start = None;
            }
            _ => {}
        }
    }
    words
}

/// `word` without its leading and trailing graphemes that hold no letter or
/// digit (punctuation such as `,` or `"`), beside the trimmed word's byte
/// offset in `word`. `None` when no grapheme holds one.
fn trimmed(word: &str) -> Option<(usize, &str)> {
    let holds = |grapheme: &str| grapheme.chars().any(char::is_alphanumeric);
    let start = word
        .grapheme_indices(true)
        .find(|(_, grapheme)| holds(grapheme))
        .map(|(idx, _)| idx)?;
    let end = word
        .grapheme_indices(true)
        .rev()
        .find(|(_, grapheme)| holds(grapheme))
        .map(|(idx, grapheme)| idx + grapheme.len())?;
    Some((start, &word[start..end]))
}
