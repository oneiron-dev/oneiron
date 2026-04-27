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

    for (idx, word) in text.unicode_word_indices() {
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

    fn stem_terms(tokens: &[Token]) -> Vec<&str> {
        tokens
            .iter()
            .filter(|t| t.channel == AnalyzerChannel::Stem)
            .map(|t| t.term.as_ref())
            .collect()
    }

    #[test]
    fn english_words_emit_surface_and_stem() {
        let mut out = Vec::new();
        analyze(
            "running runs runner",
            0,
            0,
            Some(LanguageHint::En),
            false,
            &mut out,
        );
        assert_eq!(surface_terms(&out), vec!["running", "runs", "runner"]);
        // "runner" stems to itself — no overlay emitted when stem == surface.
        assert_eq!(stem_terms(&out), vec!["run", "run"]);
    }

    #[test]
    fn casefolds_surface_term() {
        let mut out = Vec::new();
        analyze("HELLO World", 0, 0, Some(LanguageHint::En), false, &mut out);
        assert_eq!(surface_terms(&out), vec!["hello", "world"]);
    }

    #[test]
    fn offsets_refer_to_original_slice() {
        let text = "foo bar baz";
        let mut out = Vec::new();
        analyze(text, 0, 0, Some(LanguageHint::En), false, &mut out);
        for tok in &out {
            let slice = &text[tok.byte_start as usize..tok.byte_end as usize];
            assert!(!slice.is_empty());
            assert!(slice.eq_ignore_ascii_case(&tok.term));
        }
    }

    #[test]
    fn offset_base_shifts_absolute_offsets() {
        let mut out = Vec::new();
        analyze("foo bar", 100, 0, Some(LanguageHint::En), false, &mut out);
        let surface: Vec<(u32, u32)> = out
            .iter()
            .filter(|t| t.channel == AnalyzerChannel::Surface)
            .map(|t| (t.byte_start, t.byte_end))
            .collect();
        assert_eq!(surface, vec![(100, 103), (104, 107)]);
    }

    #[test]
    fn position_increments_one_per_surface_word() {
        let mut out = Vec::new();
        let next = analyze(
            "one two three",
            0,
            42,
            Some(LanguageHint::En),
            false,
            &mut out,
        );
        let positions: Vec<u32> = out
            .iter()
            .filter(|t| t.channel == AnalyzerChannel::Surface)
            .map(|t| t.position)
            .collect();
        assert_eq!(positions, vec![42, 43, 44]);
        assert_eq!(next, 45);
    }

    #[test]
    fn stem_overlay_has_zero_position_but_counts_length() {
        let mut out = Vec::new();
        analyze("running", 0, 0, Some(LanguageHint::En), false, &mut out);
        let stem = out
            .iter()
            .find(|t| t.channel == AnalyzerChannel::Stem)
            .unwrap();
        assert_eq!(stem.position_increment, 0);
        // Stem channel uses `CountLengthIncrement` normalization, so each
        // overlay must contribute to that field's length.
        assert_eq!(stem.length_increment, 1);
    }

    #[test]
    fn query_mode_still_emits_stem_overlay() {
        let mut out = Vec::new();
        analyze("running", 0, 0, Some(LanguageHint::En), true, &mut out);
        assert_eq!(surface_terms(&out), vec!["running"]);
        assert_eq!(stem_terms(&out), vec!["run"]);
    }

    #[test]
    fn no_hint_skips_stemmer_entirely() {
        let mut out = Vec::new();
        analyze("running walks", 0, 0, None, false, &mut out);
        assert!(stem_terms(&out).is_empty());
        assert_eq!(surface_terms(&out), vec!["running", "walks"]);
    }

    #[test]
    fn punctuation_does_not_produce_tokens() {
        let mut out = Vec::new();
        analyze("...,,,???", 0, 0, Some(LanguageHint::En), false, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn spanish_stemmer_reduces_inflections() {
        let mut out = Vec::new();
        analyze(
            "gatos gato gata",
            0,
            0,
            Some(LanguageHint::Es),
            false,
            &mut out,
        );
        let stems = stem_terms(&out);
        assert!(stems.iter().all(|s| s.starts_with("gat")));
    }

    #[test]
    fn russian_stemmer_reduces_inflections() {
        let mut out = Vec::new();
        analyze("кошки кошка", 0, 0, Some(LanguageHint::Ru), false, &mut out);
        let stems = stem_terms(&out);
        assert!(!stems.is_empty());
    }

    #[test]
    fn empty_input_returns_position_base() {
        let mut out = Vec::new();
        let next = analyze("", 0, 7, Some(LanguageHint::En), false, &mut out);
        assert_eq!(next, 7);
        assert!(out.is_empty());
    }

    #[test]
    fn algorithm_for_covers_all_european_hints() {
        let expected = [
            (LanguageHint::En, Algorithm::English),
            (LanguageHint::Es, Algorithm::Spanish),
            (LanguageHint::Fr, Algorithm::French),
            (LanguageHint::De, Algorithm::German),
            (LanguageHint::It, Algorithm::Italian),
            (LanguageHint::Pt, Algorithm::Portuguese),
            (LanguageHint::Nl, Algorithm::Dutch),
            (LanguageHint::Ru, Algorithm::Russian),
            (LanguageHint::Fi, Algorithm::Finnish),
            (LanguageHint::Hu, Algorithm::Hungarian),
            (LanguageHint::Sv, Algorithm::Swedish),
            (LanguageHint::No, Algorithm::Norwegian),
            (LanguageHint::Da, Algorithm::Danish),
            (LanguageHint::Ro, Algorithm::Romanian),
            (LanguageHint::Tr, Algorithm::Turkish),
            (LanguageHint::El, Algorithm::Greek),
        ];
        for (hint, algo) in expected {
            assert_eq!(algorithm_for(hint), Some(algo));
        }
    }

    #[test]
    fn algorithm_for_returns_none_for_cjk_and_sea() {
        // Includes `Ar` because Arabic routes to ICU, not Snowball.
        for hint in [
            LanguageHint::Ja,
            LanguageHint::Ko,
            LanguageHint::Zh,
            LanguageHint::Th,
            LanguageHint::Lo,
            LanguageHint::Km,
            LanguageHint::My,
            LanguageHint::Vi,
            LanguageHint::He,
            LanguageHint::Ar,
        ] {
            assert_eq!(algorithm_for(hint), None);
        }
    }
}
