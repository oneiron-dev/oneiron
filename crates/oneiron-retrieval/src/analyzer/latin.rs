//! Latin / European analyzer.
//!
//! Covers Latin, Cyrillic, Greek, and any whitespace-separated script that
//! benefits from Unicode word segmentation + optional Snowball stemming.
//! Stem algorithm selection is driven by `LanguageHint` (typically resolved
//! by `analyzer::detect`), not by script class — Cyrillic text is not
//! automatically Russian, and Latin text is not automatically English.
//!
//! Offsets on emitted tokens are **always relative to the passed-in text
//! slice**. The composer in a later commit is responsible for translating
//! them into the caller's original UTF-8 if normalization was applied.

use rust_stemmers::{Algorithm, Stemmer};
use unicode_segmentation::UnicodeSegmentation;

use super::emoji;
use super::normalize;
use super::token::{AnalyzerChannel, LanguageHint, Token, TokenKind};

pub fn algorithm_for(hint: LanguageHint) -> Option<Algorithm> {
    match hint {
        LanguageHint::En => Some(Algorithm::English),
        LanguageHint::Es => Some(Algorithm::Spanish),
        LanguageHint::Fr => Some(Algorithm::French),
        LanguageHint::De => Some(Algorithm::German),
        LanguageHint::It => Some(Algorithm::Italian),
        LanguageHint::Pt => Some(Algorithm::Portuguese),
        LanguageHint::Nl => Some(Algorithm::Dutch),
        LanguageHint::Ru => Some(Algorithm::Russian),
        LanguageHint::Fi => Some(Algorithm::Finnish),
        LanguageHint::Hu => Some(Algorithm::Hungarian),
        LanguageHint::Sv => Some(Algorithm::Swedish),
        LanguageHint::No => Some(Algorithm::Norwegian),
        LanguageHint::Da => Some(Algorithm::Danish),
        LanguageHint::Ro => Some(Algorithm::Romanian),
        LanguageHint::Tr => Some(Algorithm::Turkish),
        LanguageHint::El => Some(Algorithm::Greek),
        // Arabic routes to `icu::analyze` in the composer (script != Latin),
        // so the Snowball Arabic stemmer is unreachable through the public
        // analyzer pipeline. Keep it out of the map so the manifest's
        // `stemmer_langs` mirrors what actually executes.
        _ => None,
    }
}

/// Analyze `text` as a Latin-style run and append tokens to `out`.
///
/// Arguments:
/// * `text` — the run's UTF-8 slice.
/// * `offset_base` — byte offset of `text` inside the caller's original
///   input. Emitted tokens use `offset_base + local_offset`.
/// * `position_base` — position index for the first emitted token.
/// * `hint` — language hint; if it maps to a Snowball algorithm, a `Stem`
///   overlay is emitted at the same position whenever the stem differs
///   from the case-folded surface term.
/// * `_query_mode` — currently unused. Stems must be emitted on both index
///   and query sides, otherwise a query like `running` never probes the
///   `Stem` postings that hold `run` from a document containing `runs`.
///   Kept as a parameter for dispatch symmetry with CJK analyzers that use
///   it for overlay shaping.
///
/// Returns the next position that the caller should use when continuing
/// to emit tokens after this run.
pub fn analyze(
    text: &str,
    offset_base: u32,
    position_base: u32,
    hint: Option<LanguageHint>,
    _query_mode: bool,
    out: &mut Vec<Token>,
) -> u32 {
    if text.is_empty() {
        return position_base;
    }

    let stemmer = hint.and_then(algorithm_for).map(Stemmer::create);
    let mut position = position_base;

    // Emoji have Script=Common, so the script-run splitter attaches them to
    // an adjacent Latin/Cyrillic/Greek run (`"hello 🦀"` is ONE Latin run).
    // `unicode_word_indices` skips them as non-words, so the gaps between
    // (and around) words are scanned for emoji grapheme clusters
    // per ARCH-0031 "Emoji / unknown → Grapheme per token" (ONE-1118).
    let mut gap_start = 0usize;

    for (idx, word) in text.unicode_word_indices() {
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
        let end = start + word.len() as u32;
        let folded = normalize::casefold(word);
        let folded_str: &str = folded.as_ref();

        out.push(Token::new(
            folded_str,
            start,
            end,
            position,
            AnalyzerChannel::Surface,
            TokenKind::Word,
        ));

        if let Some(stemmer) = stemmer.as_ref() {
            let stem = stemmer.stem(folded_str);
            if stem.as_ref() != folded_str {
                out.push(
                    Token::new(
                        stem.into_owned(),
                        start,
                        end,
                        position,
                        AnalyzerChannel::Stem,
                        TokenKind::Word,
                    )
                    .overlay(),
                );
            }
        }

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
