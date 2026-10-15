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
pub(super) fn emit_emoji_graphemes(
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
