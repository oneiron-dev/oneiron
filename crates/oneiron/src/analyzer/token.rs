//! Token primitives emitted by analyzers.
//!
//! Offsets are always into the original UTF-8 input, never normalized text.

use std::fmt;

/// A single analyzer-emitted term with byte offsets and positional metadata.
///
/// `byte_start` / `byte_end` index into the original UTF-8 input. Slicing
/// `text[token.byte_start as usize..token.byte_end as usize]` must always
/// yield valid UTF-8 that corresponds to the source span this term covers.
/// Overlay channels may emit zero-width tokens at the same position as a
/// primary surface term.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Token {
    pub term: Box<str>,
    pub byte_start: u32,
    pub byte_end: u32,
    pub position: u32,
    pub position_increment: u8,
    pub position_length: u8,
    pub channel: AnalyzerChannel,
    pub length_increment: u8,
    pub kind: TokenKind,
}

impl Token {
    pub fn new(
        term: impl Into<Box<str>>,
        byte_start: u32,
        byte_end: u32,
        position: u32,
        channel: AnalyzerChannel,
        kind: TokenKind,
    ) -> Self {
        Self {
            term: term.into(),
            byte_start,
            byte_end,
            position,
            position_increment: 1,
            position_length: 1,
            channel,
            length_increment: 1,
            kind,
        }
    }

    /// Mark this token as a positional overlay: it shares its `position`
    /// with an underlying primary token so phrase queries see one
    /// position, not two. Does *not* zero `length_increment` — callers on
    /// `CountLengthIncrement` channels (e.g. CJK bigrams on `CjkNgram`,
    /// Latin stems on `Stem`) want the length-1 contribution so BM25
    /// length normalization can fire. Callers on `NoNorm` channels (e.g.
    /// `NormalizedOverlay`) chain `.with_length_increment(0)` to honor
    /// the `permits_zero_doc_field_length` contract.
    pub fn overlay(mut self) -> Self {
        self.position_increment = 0;
        self
    }

    pub fn with_length_increment(mut self, length_increment: u8) -> Self {
        self.length_increment = length_increment;
        self
    }
}

/// Logical analyzer field identifier. Each channel maps to a BM25F field.
///
/// The four v1 channels (`Surface`, `Stem`, `NormalizedOverlay`, `CjkNgram`)
/// are emitted by shipped analyzers. The reserved channels (`Shingle`,
/// `Synonym`, `Phonetic`) are storage round-trip targets but are not emitted
/// until follow-up tickets land their pipelines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AnalyzerChannel {
    Surface,
    Stem,
    NormalizedOverlay,
    CjkNgram,
    Shingle,
    Synonym,
    Phonetic,
}

impl AnalyzerChannel {
    pub const ALL_V1: [AnalyzerChannel; 4] = [
        AnalyzerChannel::Surface,
        AnalyzerChannel::Stem,
        AnalyzerChannel::NormalizedOverlay,
        AnalyzerChannel::CjkNgram,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            AnalyzerChannel::Surface => "surface",
            AnalyzerChannel::Stem => "stem",
            AnalyzerChannel::NormalizedOverlay => "normalized_overlay",
            AnalyzerChannel::CjkNgram => "cjk_ngram",
            AnalyzerChannel::Shingle => "shingle",
            AnalyzerChannel::Synonym => "synonym",
            AnalyzerChannel::Phonetic => "phonetic",
        }
    }

    pub fn field_id(self) -> u16 {
        match self {
            AnalyzerChannel::Surface => 0,
            AnalyzerChannel::Stem => 1,
            AnalyzerChannel::NormalizedOverlay => 2,
            AnalyzerChannel::CjkNgram => 3,
            AnalyzerChannel::Shingle => 4,
            AnalyzerChannel::Synonym => 5,
            AnalyzerChannel::Phonetic => 6,
        }
    }

    pub fn from_field_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(AnalyzerChannel::Surface),
            1 => Some(AnalyzerChannel::Stem),
            2 => Some(AnalyzerChannel::NormalizedOverlay),
            3 => Some(AnalyzerChannel::CjkNgram),
            4 => Some(AnalyzerChannel::Shingle),
            5 => Some(AnalyzerChannel::Synonym),
            6 => Some(AnalyzerChannel::Phonetic),
            _ => None,
        }
    }

    /// Whether this channel may legitimately persist a per-doc field
    /// length of zero while still having forward-index terms for the same
    /// doc. Overlay-style channels (JP Mode C compounds, kana-folds,
    /// synonym expansions) emit `length_increment = 0` so their tokens
    /// don't count toward `avgdl`; other channels always contribute ≥1
    /// per token. Deindex consults this to distinguish "zero because the
    /// analyzer contract says so" from "zero because the lengths row got
    /// corrupted".
    pub fn permits_zero_doc_field_length(self) -> bool {
        match self {
            AnalyzerChannel::NormalizedOverlay | AnalyzerChannel::Synonym => true,
            AnalyzerChannel::Surface
            | AnalyzerChannel::Stem
            | AnalyzerChannel::CjkNgram
            | AnalyzerChannel::Shingle
            | AnalyzerChannel::Phonetic => false,
        }
    }
}

impl fmt::Display for AnalyzerChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TokenKind {
    Word,
    Cjk,
    Numeric,
    Punct,
    Emoji,
    Unknown,
}

/// Per-analysis call context.
///
/// `query_mode` lets analyzers short-circuit overlay emission for query-side
/// text where the extra channels would only inflate IDF without improving
/// recall. `language_hint` is either set explicitly by the caller or resolved
/// by `analyzer::detect` (wired in a follow-up commit).
#[derive(Debug, Clone, Default)]
pub struct AnalyzerContext {
    pub query_mode: bool,
    pub language_hint: Option<LanguageHint>,
}

impl AnalyzerContext {
    pub fn for_index() -> Self {
        Self::default()
    }

    pub fn for_query() -> Self {
        Self {
            query_mode: true,
            language_hint: None,
        }
    }

    pub fn with_language(mut self, hint: LanguageHint) -> Self {
        self.language_hint = Some(hint);
        self
    }
}

/// Caller- or detector-supplied language tag routed to per-lang analyzers.
///
/// The variant set covers everything the rust-stemmers / whichlang / script
/// inference paths need. Variants may expand in follow-up commits; the enum
/// is `#[non_exhaustive]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LanguageHint {
    En,
    Es,
    Fr,
    De,
    It,
    Pt,
    Nl,
    Ru,
    Fi,
    Hu,
    Sv,
    No,
    Da,
    Ro,
    Tr,
    El,
    Uk,
    Pl,
    Ar,
    He,
    Ja,
    Ko,
    Zh,
    Th,
    Lo,
    Km,
    My,
    Vi,
}

impl LanguageHint {
    pub fn as_bcp47(self) -> &'static str {
        match self {
            LanguageHint::En => "en",
            LanguageHint::Es => "es",
            LanguageHint::Fr => "fr",
            LanguageHint::De => "de",
            LanguageHint::It => "it",
            LanguageHint::Pt => "pt",
            LanguageHint::Nl => "nl",
            LanguageHint::Ru => "ru",
            LanguageHint::Fi => "fi",
            LanguageHint::Hu => "hu",
            LanguageHint::Sv => "sv",
            LanguageHint::No => "no",
            LanguageHint::Da => "da",
            LanguageHint::Ro => "ro",
            LanguageHint::Tr => "tr",
            LanguageHint::El => "el",
            LanguageHint::Uk => "uk",
            LanguageHint::Pl => "pl",
            LanguageHint::Ar => "ar",
            LanguageHint::He => "he",
            LanguageHint::Ja => "ja",
            LanguageHint::Ko => "ko",
            LanguageHint::Zh => "zh",
            LanguageHint::Th => "th",
            LanguageHint::Lo => "lo",
            LanguageHint::Km => "km",
            LanguageHint::My => "my",
            LanguageHint::Vi => "vi",
        }
    }
}

impl fmt::Display for LanguageHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_bcp47())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_field_id_roundtrip() {
        for ch in [
            AnalyzerChannel::Surface,
            AnalyzerChannel::Stem,
            AnalyzerChannel::NormalizedOverlay,
            AnalyzerChannel::CjkNgram,
            AnalyzerChannel::Shingle,
            AnalyzerChannel::Synonym,
            AnalyzerChannel::Phonetic,
        ] {
            assert_eq!(AnalyzerChannel::from_field_id(ch.field_id()), Some(ch));
        }
    }

    #[test]
    fn channel_field_ids_are_contiguous_from_zero() {
        assert_eq!(AnalyzerChannel::Surface.field_id(), 0);
        assert_eq!(AnalyzerChannel::Stem.field_id(), 1);
        assert_eq!(AnalyzerChannel::NormalizedOverlay.field_id(), 2);
        assert_eq!(AnalyzerChannel::CjkNgram.field_id(), 3);
    }

    #[test]
    fn token_new_defaults_to_primary() {
        let tok = Token::new("hi", 0, 2, 0, AnalyzerChannel::Surface, TokenKind::Word);
        assert_eq!(tok.position_increment, 1);
        assert_eq!(tok.length_increment, 1);
        assert_eq!(tok.position_length, 1);
    }

    #[test]
    fn token_overlay_zeros_position_increment_only() {
        let tok = Token::new("hi", 0, 2, 0, AnalyzerChannel::NormalizedOverlay, TokenKind::Word)
            .overlay();
        assert_eq!(tok.position_increment, 0);
        assert_eq!(tok.length_increment, 1);
    }

    #[test]
    fn language_hint_bcp47_stable() {
        assert_eq!(LanguageHint::Ja.as_bcp47(), "ja");
        assert_eq!(LanguageHint::Zh.as_bcp47(), "zh");
        assert_eq!(LanguageHint::En.as_bcp47(), "en");
    }
}
