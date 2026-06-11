//! Portable-lane emoji handling: grapheme per token.
//!
//! ARCH-0031 dispatch matrix row "Emoji / unknown — Portable: Grapheme per
//! token" (ONE-1118). Word segmenters drop emoji as non-word segments, so
//! before this lane existed an emoji-only query returned nothing. The lane
//! walks a slice's extended grapheme clusters (UAX #29, via
//! `unicode-segmentation`) and emits one `Surface` token per cluster that
//! carries emoji semantics — a scalar with `Extended_Pictographic` (UTS #51,
//! covering single emoji, ZWJ sequences 👨‍👩‍👧‍👦, VS16 presentation ☂️, and
//! skin-tone bases 👍🏽), a Regional_Indicator pair (a flag 🇺🇦; UAX #29
//! GB12/GB13 group RIS in pairs, so each flag is one cluster and 🇺🇦🇯🇵 splits
//! into two), or a keycap sequence (base `0-9 # *` + optional VS16 + U+20E3,
//! e.g. 1️⃣). Each such cluster is exactly ONE token, never its constituent
//! codepoints, so the whole `Emoji / unknown` bucket is grapheme-per-token,
//! not just the pictographic subset.
//!
//! Gate semantics: clusters carrying none of those signals — punctuation,
//! whitespace — are NOT emitted here; punctuation stays dropped, and
//! numerics are unaffected because word segmenters already classify them
//! word-like upstream. ZWJ / skin-tone clustering is unchanged: it falls out
//! of the (unchanged) grapheme segmentation, recognized via the pictographic
//! signal.
//!
//! Tokens are primary (position_increment 1) with the default
//! `length_increment` of 1 — the `Surface` channel is
//! `CountLengthIncrement` per ARCH-0031 §BM25F channels, so each emoji
//! contributes to the doc field length like any other surface term.

use icu_properties::CodePointSetData;
use icu_properties::props::ExtendedPictographic;
use unicode_segmentation::UnicodeSegmentation;

use super::token::{AnalyzerChannel, Token, TokenKind};

/// COMBINING ENCLOSING KEYCAP (U+20E3): the trailing scalar of a keycap
/// sequence (e.g. `1️⃣` = `1` + VS16 + U+20E3). The keycap bases (`0-9 # *`)
/// are ASCII and not themselves emoji, so the enclosing mark is the signal
/// that the cluster belongs to the emoji lane.
const ENCLOSING_KEYCAP: char = '\u{20E3}';

/// Regional Indicator Symbols (U+1F1E6..=U+1F1FF). UAX #29 GB12/GB13 group
/// these in pairs, so a flag such as `🇺🇦` is a single grapheme cluster and a
/// run like `🇺🇦🇯🇵` splits into one cluster per flag.
#[inline]
fn is_regional_indicator(c: char) -> bool {
    matches!(c, '\u{1F1E6}'..='\u{1F1FF}')
}

/// Scan `text` for emoji grapheme clusters and append one `Surface` token per
/// cluster to `out`. A cluster qualifies when it carries a pictographic
/// scalar, a regional-indicator flag, or a keycap (U+20E3); every other
/// cluster (punctuation, whitespace) is skipped. Offsets are absolute byte
/// positions in the caller's original UTF-8 (`offset_base + local`). Returns
/// the next unused position index.
///
/// Emoji have no case or compatibility mappings that survive the upstream
/// NFKC pass, so the term is the grapheme cluster byte-for-byte — the same
/// bytes on the index and query sides, which is what makes the round-trip
/// (doc `🦀🔥` retrievable by query `🦀`) hold.
pub(crate) fn emit_emoji_graphemes(
    text: &str,
    offset_base: u32,
    position_base: u32,
    out: &mut Vec<Token>,
) -> u32 {
    // ASCII fast path: pictographics, regional indicators, and U+20E3 are all
    // non-ASCII, so a pure-ASCII slice (spaces, punctuation, bare keycap
    // bases) can never qualify and skips the grapheme walk.
    if text.is_empty() || text.is_ascii() {
        return position_base;
    }

    let pictographic = CodePointSetData::new::<ExtendedPictographic>();
    let mut position = position_base;

    for (idx, grapheme) in text.grapheme_indices(true) {
        let is_emoji = grapheme
            .chars()
            .any(|c| pictographic.contains(c) || is_regional_indicator(c) || c == ENCLOSING_KEYCAP);
        if !is_emoji {
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
        let next = emit_emoji_graphemes("🦀🔥", 0, 0, &mut out);
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
        emit_emoji_graphemes(family, 0, 0, &mut out);
        assert_eq!(out.len(), 1, "ZWJ sequence must be a single token");
        assert_eq!(out[0].term.as_ref(), family);
        assert_eq!((out[0].byte_start, out[0].byte_end), (0, 25));
    }

    #[test]
    fn skin_tone_modifier_stays_in_one_token() {
        // 👍🏽 = U+1F44D + U+1F3FD (modifier), one cluster, 8 bytes.
        let thumbs = "\u{1F44D}\u{1F3FD}";
        let mut out = Vec::new();
        emit_emoji_graphemes(thumbs, 0, 0, &mut out);
        assert_eq!(out.len(), 1, "base + skin tone must be a single token");
        assert_eq!(out[0].term.as_ref(), thumbs);
        assert_eq!((out[0].byte_start, out[0].byte_end), (0, 8));
    }

    #[test]
    fn vs16_presentation_selector_stays_in_one_token() {
        // ☂️ = U+2602 UMBRELLA (Extended_Pictographic) + U+FE0F VS16.
        let umbrella = "\u{2602}\u{FE0F}";
        let mut out = Vec::new();
        emit_emoji_graphemes(umbrella, 0, 0, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].term.as_ref(), umbrella);
    }

    #[test]
    fn regional_indicator_flag_is_one_token() {
        // 🇺🇦 = U+1F1FA U+1F1E6 (two Regional Indicators) = ONE grapheme
        // cluster = ONE flag. The contract's `Emoji / unknown → Grapheme per
        // token` row covers flags; a narrow Extended_Pictographic-only gate
        // (Extended_Pictographic=No for both RIS) would silently drop them.
        let flag = "\u{1F1FA}\u{1F1E6}";
        assert_eq!(flag.len(), 8, "two RIS, 4 bytes each");
        let mut out = Vec::new();
        let next = emit_emoji_graphemes(flag, 0, 0, &mut out);
        assert_eq!(surface_terms(&out), vec![flag], "🇺🇦 → exactly one token");
        assert_eq!(next, 1);
        assert_eq!((out[0].byte_start, out[0].byte_end), (0, 8));
        assert_eq!(out[0].kind, TokenKind::Emoji);
    }

    #[test]
    fn keycap_sequence_is_one_token() {
        // 1️⃣ = U+0031 DIGIT ONE + U+FE0F VS16 + U+20E3 ENCLOSING KEYCAP, one
        // grapheme cluster (1 + 3 + 3 = 7 bytes). The ASCII fast path does
        // not fire because U+FE0F / U+20E3 are non-ASCII. The keycap base is
        // ASCII and not pictographic, so only the U+20E3 gate emits it.
        let keycap = "\u{0031}\u{FE0F}\u{20E3}";
        assert_eq!(keycap.len(), 7);
        let mut out = Vec::new();
        let next = emit_emoji_graphemes(keycap, 0, 0, &mut out);
        assert_eq!(surface_terms(&out), vec![keycap], "1️⃣ → exactly one token");
        assert_eq!(next, 1);
        assert_eq!((out[0].byte_start, out[0].byte_end), (0, 7));
        assert_eq!(out[0].kind, TokenKind::Emoji);
    }

    #[test]
    fn adjacent_flags_split_into_two_tokens() {
        // 🇺🇦🇯🇵 = four Regional Indicators. UAX #29 GB12/GB13 break between
        // pairs, so this is exactly two clusters: 🇺🇦 then 🇯🇵 → two tokens at
        // the correct byte split, never one four-RIS blob nor four tokens.
        let ukraine = "\u{1F1FA}\u{1F1E6}";
        let japan = "\u{1F1EF}\u{1F1F5}";
        let pair = format!("{ukraine}{japan}");
        let mut out = Vec::new();
        let next = emit_emoji_graphemes(&pair, 0, 0, &mut out);
        assert_eq!(surface_terms(&out), vec![ukraine, japan]);
        assert_eq!(next, 2);
        assert_eq!((out[0].byte_start, out[0].byte_end), (0, 8));
        assert_eq!((out[1].byte_start, out[1].byte_end), (8, 16));
    }

    #[test]
    fn punctuation_and_whitespace_emit_nothing() {
        let mut out = Vec::new();
        let next = emit_emoji_graphemes("  ...!!?,、。", 0, 5, &mut out);
        assert!(out.is_empty(), "punctuation must stay dropped");
        assert_eq!(next, 5, "position must not advance");
    }

    #[test]
    fn emoji_amid_punctuation_emits_only_emoji() {
        let text = "(🦀, 🔥!)";
        let mut out = Vec::new();
        emit_emoji_graphemes(text, 0, 0, &mut out);
        assert_eq!(surface_terms(&out), vec!["🦀", "🔥"]);
    }

    #[test]
    fn ascii_fast_path_emits_nothing() {
        let mut out = Vec::new();
        let next = emit_emoji_graphemes("abc 123", 0, 3, &mut out);
        assert!(out.is_empty());
        assert_eq!(next, 3);
    }

    #[test]
    fn offset_and_position_bases_are_respected() {
        let mut out = Vec::new();
        let next = emit_emoji_graphemes("🦀", 100, 7, &mut out);
        assert_eq!(next, 8);
        assert_eq!((out[0].byte_start, out[0].byte_end), (100, 104));
        assert_eq!(out[0].position, 7);
    }
}
