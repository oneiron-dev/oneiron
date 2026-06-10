//! Portable-lane emoji handling: grapheme per token.
//!
//! ARCH-0031 dispatch matrix row "Emoji / unknown — Portable: Grapheme per
//! token" (ONE-1118). Word segmenters drop emoji as non-word segments, so
//! before this lane existed an emoji-only query returned nothing. The lane
//! walks a slice's extended grapheme clusters (UAX #29, via
//! `unicode-segmentation`) and emits one `Surface` token per cluster that
//! contains at least one `Extended_Pictographic` scalar (UTS #51) — so a
//! ZWJ sequence (👨‍👩‍👧‍👦) or a skin-tone modified base (👍🏽) is exactly ONE
//! token, never its constituent codepoints.
//!
//! Gate semantics: the ticket pins `Extended_Pictographic` as the gate.
//! Clusters without any pictographic scalar — punctuation, whitespace,
//! regional-indicator flag pairs (🇺🇦), bare keycap sequences — are NOT
//! emitted here; punctuation stays dropped, and numerics are unaffected
//! because word segmenters already classify them word-like upstream.
//!
//! Tokens are primary (position_increment 1) with the default
//! `length_increment` of 1 — the `Surface` channel is
//! `CountLengthIncrement` per ARCH-0031 §BM25F channels, so each emoji
//! contributes to the doc field length like any other surface term.

use icu_properties::CodePointSetData;
use icu_properties::props::ExtendedPictographic;
use unicode_segmentation::UnicodeSegmentation;

use super::token::{AnalyzerChannel, Token, TokenKind};

/// Scan `text` for extended-pictographic grapheme clusters and append one
/// `Surface` token per cluster to `out`. Non-pictographic clusters are
/// skipped. Offsets are absolute byte positions in the caller's original
/// UTF-8 (`offset_base + local`). Returns the next unused position index.
///
/// Emoji have no case or compatibility mappings that survive the upstream
/// NFKC pass, so the term is the grapheme cluster byte-for-byte — the same
/// bytes on the index and query sides, which is what makes the round-trip
/// (doc `🦀🔥` retrievable by query `🦀`) hold.
pub(crate) fn emit_pictographic_graphemes(
    text: &str,
    offset_base: u32,
    position_base: u32,
    out: &mut Vec<Token>,
) -> u32 {
    // ASCII fast path: Extended_Pictographic has no ASCII members, so
    // pure-ASCII gaps (spaces, punctuation runs) skip the grapheme walk.
    if text.is_empty() || text.is_ascii() {
        return position_base;
    }

    let pictographic = CodePointSetData::new::<ExtendedPictographic>();
    let mut position = position_base;

    for (idx, grapheme) in text.grapheme_indices(true) {
        if !grapheme.chars().any(|c| pictographic.contains(c)) {
            continue;
        }
        let start = offset_base + idx as u32;
        let end = start + grapheme.len() as u32;
        out.push(Token::new(
            grapheme,
            start,
            end,
            position,
            AnalyzerChannel::Surface,
            TokenKind::Emoji,
        ));
        position += 1;
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
    fn crab_and_fire_emit_one_token_each() {
        let mut out = Vec::new();
        let next = emit_pictographic_graphemes("🦀🔥", 0, 0, &mut out);
        assert_eq!(surface_terms(&out), vec!["🦀", "🔥"]);
        assert_eq!(next, 2);
        // 🦀 = U+1F980 (4 bytes), 🔥 = U+1F525 (4 bytes).
        assert_eq!((out[0].byte_start, out[0].byte_end), (0, 4));
        assert_eq!((out[1].byte_start, out[1].byte_end), (4, 8));
        for (i, tok) in out.iter().enumerate() {
            assert_eq!(tok.position, i as u32);
            assert_eq!(tok.position_increment, 1, "emoji tokens are primary");
            assert_eq!(
                tok.length_increment, 1,
                "AC1: emoji tokens carry length_increment 1"
            );
            assert_eq!(tok.kind, TokenKind::Emoji);
        }
    }

    #[test]
    fn zwj_family_is_exactly_one_token() {
        // 👨‍👩‍👧‍👦 = MAN, ZWJ, WOMAN, ZWJ, GIRL, ZWJ, BOY = 7 scalars, 25 bytes,
        // ONE extended grapheme cluster. A codepoint-per-token
        // implementation would emit 4 (or 7) tokens here and fail.
        let family = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}\u{200D}\u{1F466}";
        assert_eq!(family.len(), 25);
        let mut out = Vec::new();
        emit_pictographic_graphemes(family, 0, 0, &mut out);
        assert_eq!(out.len(), 1, "ZWJ sequence must be a single token");
        assert_eq!(out[0].term.as_ref(), family);
        assert_eq!((out[0].byte_start, out[0].byte_end), (0, 25));
    }

    #[test]
    fn skin_tone_modifier_stays_in_one_token() {
        // 👍🏽 = U+1F44D + U+1F3FD (modifier), one cluster, 8 bytes.
        let thumbs = "\u{1F44D}\u{1F3FD}";
        let mut out = Vec::new();
        emit_pictographic_graphemes(thumbs, 0, 0, &mut out);
        assert_eq!(out.len(), 1, "base + skin tone must be a single token");
        assert_eq!(out[0].term.as_ref(), thumbs);
        assert_eq!((out[0].byte_start, out[0].byte_end), (0, 8));
    }

    #[test]
    fn vs16_presentation_selector_stays_in_one_token() {
        // ☂️ = U+2602 UMBRELLA (Extended_Pictographic) + U+FE0F VS16.
        let umbrella = "\u{2602}\u{FE0F}";
        let mut out = Vec::new();
        emit_pictographic_graphemes(umbrella, 0, 0, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].term.as_ref(), umbrella);
    }

    #[test]
    fn punctuation_and_whitespace_emit_nothing() {
        let mut out = Vec::new();
        let next = emit_pictographic_graphemes("  ...!!?,、。", 0, 5, &mut out);
        assert!(out.is_empty(), "punctuation must stay dropped");
        assert_eq!(next, 5, "position must not advance");
    }

    #[test]
    fn emoji_amid_punctuation_emits_only_emoji() {
        let text = "(🦀, 🔥!)";
        let mut out = Vec::new();
        emit_pictographic_graphemes(text, 0, 0, &mut out);
        assert_eq!(surface_terms(&out), vec!["🦀", "🔥"]);
    }

    #[test]
    fn regional_indicator_flags_are_not_extended_pictographic() {
        // 🇺🇦 = two regional indicators; Extended_Pictographic=No for both.
        // The ticket pins the Extended_Pictographic gate, so flag pairs are
        // intentionally not emitted by this lane (documented limitation).
        let mut out = Vec::new();
        emit_pictographic_graphemes("\u{1F1FA}\u{1F1E6}", 0, 0, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn ascii_fast_path_emits_nothing() {
        let mut out = Vec::new();
        let next = emit_pictographic_graphemes("abc 123", 0, 3, &mut out);
        assert!(out.is_empty());
        assert_eq!(next, 3);
    }

    #[test]
    fn offset_and_position_bases_are_respected() {
        let mut out = Vec::new();
        let next = emit_pictographic_graphemes("🦀", 100, 7, &mut out);
        assert_eq!(next, 8);
        assert_eq!((out[0].byte_start, out[0].byte_end), (100, 104));
        assert_eq!(out[0].position, 7);
    }
}
