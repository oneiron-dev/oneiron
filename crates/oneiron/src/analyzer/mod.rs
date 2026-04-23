//! Multilingual analyzer subsystem.
//!
//! [`MultilingualAnalyzer`] is the single user-facing analyzer. It owns a
//! [`ScriptRunSplitter`] plus one per-CJK-lang sub-analyzer
//! ([`JapaneseAnalyzer`], [`ChineseAnalyzer`], [`KoreanAnalyzer`]) and
//! dispatches each script run to the right backend per plan §7.
//!
//! Dict discovery happens once at [`MultilingualAnalyzer::discover`] time;
//! each per-lang backend probes [`VaultConfig::dict_search_paths`] (plan
//! §2.3) and caches its loaded dict. The resulting [`AnalyzerManifest`]
//! reports the per-lang mode (Morphological / Portable) and — when a dict
//! was loaded — the dict's license + version. The manifest is what gates
//! LMDB text-index compatibility; opening an index whose on-disk manifest
//! hash no longer matches the current analyzer must fail closed (plan §4.2).
//!
//! Han-only runs with no language hint invoke the "DualHanFallback" of
//! plan §1.2: prefer the Japanese dict when both JP and ZH dicts are
//! loaded, else use whichever is present, else fall through to
//! [`cjk_ngram::analyze`]. The picked backend still emits on `Surface` +
//! `CjkNgram`; the ambiguity matters only for morpheme segmentation, not
//! for the character-bigram overlay.

pub mod chinese;
pub mod cjk_ngram;
pub mod detect;
pub mod icu;
pub mod japanese;
pub mod korean;
pub mod latin;
pub mod manifest;
pub mod normalize;
pub mod script;
pub mod token;

use std::collections::BTreeMap;
use std::path::PathBuf;

pub use manifest::{
    ANALYZER_VERSION, AnalyzerAssetManifest, AnalyzerManifest, AnalyzerMode, LangPolicy,
    NormalizationPolicy, canonical_hash, canonical_hash_hex, canonical_json,
};
pub use detect::{DETECT_WINDOW_BYTES, PerDocCache};
pub use normalize::NormalizedText;
pub use script::{ScriptClass, ScriptRun, ScriptRunSplitter};
pub use token::{AnalyzerChannel, AnalyzerContext, LanguageHint, Token, TokenKind};

use chinese::ChineseAnalyzer;
use japanese::JapaneseAnalyzer;
use korean::KoreanAnalyzer;

/// The single multilingual analyzer. Routes each script run to the right
/// per-lang backend and handles DualHanFallback for ambiguous Han runs.
#[derive(Debug, Clone)]
pub struct MultilingualAnalyzer {
    splitter: ScriptRunSplitter,
    japanese: JapaneseAnalyzer,
    chinese: ChineseAnalyzer,
    korean: KoreanAnalyzer,
    normalization: NormalizationPolicy,
}

impl MultilingualAnalyzer {
    /// Build an analyzer with all per-lang backends in Portable mode.
    /// Useful for tests and for callers who explicitly don't want any
    /// morphological dicts loaded.
    pub fn portable() -> Self {
        Self {
            splitter: ScriptRunSplitter::new(),
            japanese: JapaneseAnalyzer::portable(),
            chinese: ChineseAnalyzer::portable(),
            korean: KoreanAnalyzer::portable(),
            normalization: NormalizationPolicy::default(),
        }
    }

    /// Build an analyzer by probing `search_paths` for each per-lang dict.
    /// Returns an error only when a dict file is present but fails to load
    /// (corrupt / wrong format). A missing dict silently downgrades that
    /// lang to Portable.
    pub fn discover(search_paths: &[PathBuf]) -> Result<Self, DiscoverError> {
        let japanese = JapaneseAnalyzer::discover(search_paths)
            .map_err(|source| DiscoverError::Japanese { source })?;
        let chinese = ChineseAnalyzer::discover(search_paths)
            .map_err(|source| DiscoverError::Chinese { source })?;
        let korean = KoreanAnalyzer::discover(search_paths)
            .map_err(|source| DiscoverError::Korean { source })?;
        Ok(Self {
            splitter: ScriptRunSplitter::new(),
            japanese,
            chinese,
            korean,
            normalization: NormalizationPolicy::default(),
        })
    }

    pub fn japanese(&self) -> &JapaneseAnalyzer {
        &self.japanese
    }

    pub fn chinese(&self) -> &ChineseAnalyzer {
        &self.chinese
    }

    pub fn korean(&self) -> &KoreanAnalyzer {
        &self.korean
    }

    pub fn normalization(&self) -> &NormalizationPolicy {
        &self.normalization
    }

    /// Analyze `text` and append tokens to `out`. Returns the next unused
    /// position index. Offsets on every emitted token are absolute byte
    /// positions into the caller's `text` — even when normalization
    /// rewrites the input, offsets are remapped back through the
    /// [`NormalizedText`] boundary table (plan §3.3).
    pub fn analyze(&self, text: &str, ctx: &AnalyzerContext, out: &mut Vec<Token>) -> u32 {
        if text.is_empty() {
            return 0;
        }

        // Pre-tokenization normalization (plan §6). Segmentation and
        // every sub-analyzer see the *normalized* slice so NFKC'd forms
        // like ＡＢＣ or ｶﾀｶﾅ reach the same postings as their canonical
        // counterparts. Emitted offsets are remapped at the end.
        let normalized = normalize::normalize_with_offset_map(text, &self.normalization);
        let analysis_text = normalized.as_str();

        let runs = self.splitter.runs(analysis_text);
        let mut cache = PerDocCache::new();
        let mut position: u32 = 0;
        let token_start = out.len();

        for run in &runs {
            let slice = run.as_slice(analysis_text);
            let run_hint = detect::infer_from_script(run.script)
                .or_else(|| cache.resolve(ctx.language_hint, &runs, analysis_text));
            position = self.dispatch_run(run, slice, run_hint, ctx.query_mode, position, out);
        }

        if !normalized.is_unchanged() {
            for tok in &mut out[token_start..] {
                tok.byte_start = normalized.remap(tok.byte_start);
                tok.byte_end = normalized.remap(tok.byte_end);
            }
        }

        position
    }

    fn dispatch_run(
        &self,
        run: &ScriptRun,
        slice: &str,
        hint: Option<LanguageHint>,
        query_mode: bool,
        position_base: u32,
        out: &mut Vec<Token>,
    ) -> u32 {
        let offset_base = run.byte_start;

        match run.script {
            ScriptClass::Hiragana | ScriptClass::Katakana => {
                self.japanese
                    .analyze(slice, offset_base, position_base, query_mode, out)
            }
            ScriptClass::Hangul => {
                self.korean
                    .analyze(slice, offset_base, position_base, query_mode, out)
            }
            ScriptClass::Han => {
                self.dispatch_han(slice, offset_base, position_base, hint, query_mode, out)
            }
            ScriptClass::Latin | ScriptClass::Cyrillic | ScriptClass::Greek => {
                latin::analyze(slice, offset_base, position_base, hint, query_mode, out)
            }
            ScriptClass::Arabic | ScriptClass::Hebrew => {
                // Diacritic / niqqud stripping deferred (plan §6, §14) — v1
                // tokenizes via ICU4X word-break only.
                icu::analyze(slice, offset_base, position_base, out)
            }
            ScriptClass::Thai
            | ScriptClass::Lao
            | ScriptClass::Khmer
            | ScriptClass::Myanmar
            | ScriptClass::Devanagari
            | ScriptClass::Tamil => icu::analyze(slice, offset_base, position_base, out),
            ScriptClass::Common | ScriptClass::Other => {
                // Pure-Common runs (punctuation, digits, emoji) still go
                // through ICU4X so numerics become Surface tokens; other
                // non-word segments are dropped by the segmenter itself.
                icu::analyze(slice, offset_base, position_base, out)
            }
        }
    }

    /// DualHanFallback (plan §1.2): Han-only runs are ambiguous between JP
    /// kanji and ZH. If the caller gave an explicit hint we honor it;
    /// otherwise we prefer whichever dict is loaded. With neither loaded
    /// we fall through to [`cjk_ngram::analyze`].
    fn dispatch_han(
        &self,
        slice: &str,
        offset_base: u32,
        position_base: u32,
        hint: Option<LanguageHint>,
        query_mode: bool,
        out: &mut Vec<Token>,
    ) -> u32 {
        let ja_has_dict = matches!(self.japanese.mode(), AnalyzerMode::Morphological);
        let zh_has_dict = matches!(self.chinese.mode(), AnalyzerMode::Morphological);

        let prefer_ja = match hint {
            Some(LanguageHint::Ja) => true,
            Some(LanguageHint::Zh) => false,
            _ => ja_has_dict || !zh_has_dict,
        };

        if prefer_ja && ja_has_dict {
            self.japanese
                .analyze(slice, offset_base, position_base, query_mode, out)
        } else if zh_has_dict {
            self.chinese
                .analyze(slice, offset_base, position_base, query_mode, out)
        } else if ja_has_dict {
            self.japanese
                .analyze(slice, offset_base, position_base, query_mode, out)
        } else {
            cjk_ngram::analyze(slice, offset_base, position_base, out)
        }
    }

    /// Canonical manifest for this analyzer configuration. Gates LMDB
    /// text-index compatibility (plan §4.2). The per-lang `dict` field is
    /// populated from each backend's [`asset_manifest`] so the manifest
    /// hash binds not just to mode (Morph/Portable) but to the exact dict
    /// bytes — a dict swap forces a reindex via fail-closed handshake.
    pub fn manifest(&self) -> AnalyzerManifest {
        let mut langs: BTreeMap<String, LangPolicy> = BTreeMap::new();
        langs.insert(
            "ja".into(),
            LangPolicy {
                mode: self.japanese.mode(),
                dict: self.japanese.asset_manifest().cloned(),
            },
        );
        langs.insert(
            "zh".into(),
            LangPolicy {
                mode: self.chinese.mode(),
                dict: self.chinese.asset_manifest().cloned(),
            },
        );
        langs.insert(
            "ko".into(),
            LangPolicy {
                mode: self.korean.mode(),
                dict: self.korean.asset_manifest().cloned(),
            },
        );
        langs.insert(
            "*".into(),
            LangPolicy {
                mode: AnalyzerMode::Portable,
                dict: None,
            },
        );

        AnalyzerManifest {
            analyzer_version: ANALYZER_VERSION.into(),
            normalization: self.normalization.clone(),
            langs,
            channels: AnalyzerChannel::ALL_V1
                .iter()
                .map(|c| c.as_str().to_string())
                .collect(),
            stemmer_langs: vec![
                "en".into(),
                "es".into(),
                "fr".into(),
                "de".into(),
                "it".into(),
                "pt".into(),
                "nl".into(),
                "ru".into(),
                "fi".into(),
                "hu".into(),
                "sv".into(),
                "no".into(),
                "da".into(),
                "ro".into(),
                "tr".into(),
                "el".into(),
                "ar".into(),
            ],
        }
    }
}

impl Default for MultilingualAnalyzer {
    fn default() -> Self {
        Self::portable()
    }
}

/// Errors returned from [`MultilingualAnalyzer::discover`] when a dict
/// file exists on disk but fails to load. Missing dicts are not errors —
/// they silently downgrade the affected lang to Portable.
#[derive(Debug, thiserror::Error)]
pub enum DiscoverError {
    #[error("japanese dict load failed: {source}")]
    Japanese {
        #[source]
        source: japanese::DictLoadError,
    },
    #[error("chinese dict load failed: {source}")]
    Chinese {
        #[source]
        source: chinese::DictLoadError,
    },
    #[error("korean dict load failed: {source}")]
    Korean {
        #[source]
        source: korean::DictLoadError,
    },
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
    fn portable_analyzer_reports_portable_for_all_cjk() {
        let a = MultilingualAnalyzer::portable();
        let m = a.manifest();
        assert_eq!(m.langs["ja"].mode, AnalyzerMode::Portable);
        assert_eq!(m.langs["zh"].mode, AnalyzerMode::Portable);
        assert_eq!(m.langs["ko"].mode, AnalyzerMode::Portable);
        assert_eq!(m.langs["*"].mode, AnalyzerMode::Portable);
    }

    #[test]
    fn manifest_channels_match_v1() {
        let a = MultilingualAnalyzer::portable();
        let m = a.manifest();
        assert_eq!(m.channels, vec!["surface", "stem", "normalized_overlay", "cjk_ngram"]);
    }

    #[test]
    fn manifest_hash_stable() {
        let a = MultilingualAnalyzer::portable();
        let h1 = a.manifest().canonical_hash().unwrap();
        let h2 = a.manifest().canonical_hash().unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn empty_input_returns_zero() {
        let a = MultilingualAnalyzer::portable();
        let mut out = Vec::new();
        let next = a.analyze("", &AnalyzerContext::for_index(), &mut out);
        assert_eq!(next, 0);
        assert!(out.is_empty());
    }

    #[test]
    fn latin_routes_to_latin_analyzer_with_detected_hint() {
        let a = MultilingualAnalyzer::portable();
        let mut out = Vec::new();
        a.analyze(
            "The quick brown fox jumps over the lazy dog",
            &AnalyzerContext::for_index(),
            &mut out,
        );
        // English stemmer should produce at least one stem overlay.
        let stems: Vec<_> = out
            .iter()
            .filter(|t| t.channel == AnalyzerChannel::Stem)
            .collect();
        assert!(!stems.is_empty(), "expected stem overlays for English text");
    }

    #[test]
    fn hiragana_routes_to_japanese_portable() {
        let a = MultilingualAnalyzer::portable();
        let mut out = Vec::new();
        a.analyze("とうきょう", &AnalyzerContext::for_index(), &mut out);
        // Portable JP falls through to cjk_ngram → per-char unigrams on Surface.
        let terms = surface_terms(&out);
        assert_eq!(terms, vec!["と", "う", "き", "ょ", "う"]);
    }

    #[test]
    fn hangul_routes_to_korean_portable() {
        let a = MultilingualAnalyzer::portable();
        let mut out = Vec::new();
        a.analyze("안녕하세요", &AnalyzerContext::for_index(), &mut out);
        let terms = surface_terms(&out);
        assert_eq!(terms, vec!["안", "녕", "하", "세", "요"]);
    }

    #[test]
    fn han_portable_produces_unigrams_and_bigram_overlay() {
        let a = MultilingualAnalyzer::portable();
        let mut out = Vec::new();
        a.analyze("東京大学", &AnalyzerContext::for_index(), &mut out);
        let surface = surface_terms(&out);
        assert_eq!(surface, vec!["東", "京", "大", "学"]);
        let bigrams: Vec<&str> = out
            .iter()
            .filter(|t| t.channel == AnalyzerChannel::CjkNgram)
            .map(|t| t.term.as_ref())
            .collect();
        assert_eq!(bigrams, vec!["東京", "京大", "大学"]);
    }

    #[test]
    fn mixed_script_no_cross_boundary_bigram() {
        let a = MultilingualAnalyzer::portable();
        let text = "とう東京";
        let mut out = Vec::new();
        a.analyze(text, &AnalyzerContext::for_index(), &mut out);
        // Any cjk_ngram token must not span the hiragana→han boundary.
        // `とう` ends at byte 6; `東京` starts at byte 6. Reject any token
        // whose [start, end) crosses the boundary of 6.
        for tok in out.iter().filter(|t| t.channel == AnalyzerChannel::CjkNgram) {
            let s = tok.byte_start as usize;
            let e = tok.byte_end as usize;
            assert!(
                e <= 6 || s >= 6,
                "bigram {:?} [{}..{}] crosses script boundary at byte 6",
                tok.term,
                s,
                e,
            );
        }
    }

    #[test]
    fn cjk_digit_mix_no_cross_boundary_bigram() {
        let a = MultilingualAnalyzer::portable();
        // `東京` ends at byte 6; `123` starts at byte 6. No cjk_ngram token
        // may span byte 6, and no cjk_ngram token may contain ASCII digits.
        let text = "東京123";
        let mut out = Vec::new();
        a.analyze(text, &AnalyzerContext::for_index(), &mut out);
        for tok in out.iter().filter(|t| t.channel == AnalyzerChannel::CjkNgram) {
            let s = tok.byte_start as usize;
            let e = tok.byte_end as usize;
            assert!(
                e <= 6 || s >= 6,
                "bigram {:?} [{}..{}] crosses script boundary at byte 6",
                tok.term,
                s,
                e,
            );
            assert!(
                !tok.term.chars().any(|c| c.is_ascii_digit()),
                "cjk_ngram token {:?} must not contain ASCII digits",
                tok.term,
            );
        }
    }

    #[test]
    fn cjk_with_leading_common_no_cross_boundary_bigram() {
        let a = MultilingualAnalyzer::portable();
        // `2024` 0..4, `東京` 4..10. No cjk_ngram token may contain an
        // ASCII digit, and no cjk_ngram token may span byte 4.
        let text = "2024東京";
        let mut out = Vec::new();
        a.analyze(text, &AnalyzerContext::for_index(), &mut out);
        for tok in out.iter().filter(|t| t.channel == AnalyzerChannel::CjkNgram) {
            let s = tok.byte_start as usize;
            let e = tok.byte_end as usize;
            assert!(
                s >= 4,
                "cjk_ngram {:?} [{}..{}] must start at/after the CJK boundary (byte 4)",
                tok.term,
                s,
                e,
            );
            assert!(
                !tok.term.chars().any(|c| c.is_ascii_digit()),
                "cjk_ngram token {:?} must not contain ASCII digits",
                tok.term,
            );
        }
    }

    #[test]
    fn cjk_punct_mix_no_cross_boundary_bigram() {
        let a = MultilingualAnalyzer::portable();
        // `北京` 0..6, `、` 6..9, `大学` 9..15. No cjk_ngram may contain the
        // fullwidth comma or span across it.
        let text = "北京、大学";
        let mut out = Vec::new();
        a.analyze(text, &AnalyzerContext::for_index(), &mut out);
        for tok in out.iter().filter(|t| t.channel == AnalyzerChannel::CjkNgram) {
            let s = tok.byte_start as usize;
            let e = tok.byte_end as usize;
            assert!(
                (e <= 6) || (s >= 9),
                "bigram {:?} [{}..{}] crosses CJK/punct boundary",
                tok.term,
                s,
                e,
            );
            assert!(
                !tok.term.contains('、'),
                "cjk_ngram token {:?} must not contain fullwidth comma",
                tok.term,
            );
        }
    }

    #[test]
    fn thai_routes_to_icu_segmenter() {
        let a = MultilingualAnalyzer::portable();
        let mut out = Vec::new();
        a.analyze("ไปโรงเรียน", &AnalyzerContext::for_index(), &mut out);
        // ICU4X returns at least one word-like segment for Thai.
        assert!(!surface_terms(&out).is_empty());
    }

    #[test]
    fn offsets_slice_original_utf8() {
        let a = MultilingualAnalyzer::portable();
        let text = "hello 東京 안녕 สวัสดี";
        let mut out = Vec::new();
        a.analyze(text, &AnalyzerContext::for_index(), &mut out);
        for tok in &out {
            let s = tok.byte_start as usize;
            let e = tok.byte_end as usize;
            assert!(s <= e && e <= text.len());
            // Slicing must not panic — this enforces valid UTF-8 boundaries.
            let _ = &text[s..e];
        }
    }

    #[test]
    fn positions_monotonic_across_runs() {
        let a = MultilingualAnalyzer::portable();
        let mut out = Vec::new();
        a.analyze("hello 東京", &AnalyzerContext::for_index(), &mut out);
        let mut last = 0u32;
        for tok in out.iter().filter(|t| t.channel == AnalyzerChannel::Surface) {
            assert!(tok.position >= last);
            last = tok.position;
        }
    }

    #[test]
    fn discover_with_no_paths_returns_all_portable() {
        let a = MultilingualAnalyzer::discover(&[]).unwrap();
        let m = a.manifest();
        assert_eq!(m.langs["ja"].mode, AnalyzerMode::Portable);
        assert_eq!(m.langs["zh"].mode, AnalyzerMode::Portable);
        assert_eq!(m.langs["ko"].mode, AnalyzerMode::Portable);
    }

    #[test]
    fn fullwidth_ascii_folds_to_ascii_with_original_offsets() {
        let a = MultilingualAnalyzer::portable();
        let text = "ＡＢＣ";
        let mut out = Vec::new();
        a.analyze(text, &AnalyzerContext::for_index(), &mut out);
        let surface = surface_terms(&out);
        assert_eq!(surface, vec!["abc"]);
        let tok = &out[0];
        // Offsets must reference the ORIGINAL UTF-8 (9 bytes), not the
        // normalized form (3 bytes).
        assert_eq!(tok.byte_start, 0);
        assert_eq!(tok.byte_end, text.len() as u32);
        let slice = &text[tok.byte_start as usize..tok.byte_end as usize];
        assert_eq!(slice, "ＡＢＣ");
    }

    #[test]
    fn halfwidth_katakana_indexes_like_fullwidth() {
        let a = MultilingualAnalyzer::portable();
        let mut half = Vec::new();
        let mut full = Vec::new();
        a.analyze("ｶﾀｶﾅ", &AnalyzerContext::for_index(), &mut half);
        a.analyze("カタカナ", &AnalyzerContext::for_index(), &mut full);
        // After NFKC, halfwidth katakana indexes the same surface terms
        // as the fullwidth form. Byte offsets differ since the sources
        // have different lengths — equality of terms is what matters.
        assert_eq!(surface_terms(&half), surface_terms(&full));
    }

    #[test]
    fn original_offsets_survive_mixed_normalization() {
        // Mixed-script sample with a fullwidth-ASCII prefix; every emitted
        // token must still slice valid UTF-8 out of the ORIGINAL input.
        let a = MultilingualAnalyzer::portable();
        let text = "ＡＢＣ 東京";
        let mut out = Vec::new();
        a.analyze(text, &AnalyzerContext::for_index(), &mut out);
        assert!(!out.is_empty());
        for tok in &out {
            let s = tok.byte_start as usize;
            let e = tok.byte_end as usize;
            assert!(s <= e && e <= text.len(), "offsets out of range: {s}..{e}");
            let _ = &text[s..e];
        }
        assert!(surface_terms(&out).contains(&"abc"));
    }

    #[test]
    fn explicit_japanese_hint_on_han_only_run_prefers_japanese_path() {
        // No dicts loaded in Portable mode — both paths fall through to
        // cjk_ngram, so the observable output is identical. But dispatch
        // must not panic when the hint is Ja on Han text.
        let a = MultilingualAnalyzer::portable();
        let mut out = Vec::new();
        let ctx = AnalyzerContext::for_index().with_language(LanguageHint::Ja);
        a.analyze("東京", &ctx, &mut out);
        assert_eq!(surface_terms(&out), vec!["東", "京"]);
    }
}
