//! Multilingual analyzer subsystem.
//!
//! [`MultilingualAnalyzer`] is the single user-facing analyzer. It owns a
//! [`ScriptRunSplitter`] plus one per-CJK-lang sub-analyzer
//! ([`JapaneseAnalyzer`], [`ChineseAnalyzer`], [`KoreanAnalyzer`]) and
//! dispatches each script run to the right backend per plan §7.
//!
//! Dict discovery happens once at [`MultilingualAnalyzer::discover`] time;
//! each per-lang backend probes [`crate::VaultConfig::dict_search_paths`] (plan
//! §2.3) and caches its loaded dict. The resulting [`AnalyzerManifest`]
//! reports the per-lang mode (Morphological / Portable) and — when a dict
//! was loaded — the dict's license + version. The manifest is what gates
//! LMDB text-index compatibility; opening an index whose on-disk manifest
//! hash no longer matches the current analyzer must fail closed (plan §4.2).
//!
//! Han-only runs can receive explicit or detector-derived `Ja`/`Zh` hints
//! and route directly to the hinted analyzer. If no usable hint exists,
//! they invoke the "DualHanFallback" of plan §1.2: prefer the Japanese dict
//! when both JP and ZH dicts are loaded, else use whichever is present, else
//! fall through to [`cjk_ngram::analyze`]. The picked backend still emits on
//! `Surface` + `CjkNgram`; the ambiguity matters only for morpheme
//! segmentation, not for the character-bigram overlay.

pub mod chinese;
pub mod cjk_ngram;
pub mod detect;
pub(crate) mod emoji;
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

pub use detect::DETECT_WINDOW_BYTES;
pub use manifest::{
    ANALYZER_VERSION, AnalyzerAssetManifest, AnalyzerManifest, AnalyzerMode, LangPolicy,
    NormalizationPolicy, canonical_hash, canonical_hash_hex, canonical_json,
};
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
        let mut position: u32 = 0;
        let token_start = out.len();

        for run in &runs {
            let slice = run.as_slice(analysis_text);
            // Resolve hint per run so a CJK run cannot poison an adjacent
            // Latin run's stemmer selection. `detect_with_whichlang` runs on
            // the run's own bytes, not on cross-run analysis_text. We skip
            // whichlang when script inference already yields a hint, or when
            // the downstream analyzer ignores language hints.
            let run_hint = detect::infer_from_script(run.script)
                .or(ctx.language_hint)
                .or_else(|| {
                    if whichlang_eligible(run.script) {
                        detect::detect_with_whichlang(slice)
                    } else {
                        None
                    }
                });
            position = self.dispatch_run(run, slice, run_hint, ctx.query_mode, position, out);
        }

        if !normalized.is_unchanged() {
            for tok in &mut out[token_start..] {
                tok.byte_start = normalized.remap(tok.byte_start);
                tok.byte_end = normalized.remap_end(tok.byte_end);
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
                // Pure-Common runs (punctuation, digits, emoji) go through
                // ICU4X so numerics become Surface tokens; the ICU lane's
                // non-word segments are additionally scanned for emoji
                // grapheme clusters (pictographics, flags, keycaps),
                // emitting one Surface token per grapheme cluster (ARCH-0031
                // dispatch row "Emoji / unknown → Grapheme per token",
                // ONE-1118). Remaining non-word segments (punctuation,
                // whitespace) stay dropped.
                icu::analyze(slice, offset_base, position_base, out)
            }
        }
    }

    /// Han-only runs are ambiguous between JP kanji and ZH. Explicit caller
    /// hints and detector-derived `Ja`/`Zh` hints are authoritative: they
    /// route to the hinted analyzer regardless of dict presence, and the
    /// sub-analyzer's portable path handles the dict-absent case.
    ///
    /// If no usable hint exists, DualHanFallback (plan §1.2) prefers
    /// whichever dict is loaded (JP first when both); with neither loaded we
    /// fall through to [`cjk_ngram::analyze`].
    fn dispatch_han(
        &self,
        slice: &str,
        offset_base: u32,
        position_base: u32,
        hint: Option<LanguageHint>,
        query_mode: bool,
        out: &mut Vec<Token>,
    ) -> u32 {
        match hint {
            Some(LanguageHint::Ja) => {
                return self
                    .japanese
                    .analyze(slice, offset_base, position_base, query_mode, out);
            }
            Some(LanguageHint::Zh) => {
                return self
                    .chinese
                    .analyze(slice, offset_base, position_base, query_mode, out);
            }
            _ => {}
        }

        let ja_has_dict = matches!(self.japanese.mode(), AnalyzerMode::Morphological);
        let zh_has_dict = matches!(self.chinese.mode(), AnalyzerMode::Morphological);

        if ja_has_dict {
            self.japanese
                .analyze(slice, offset_base, position_base, query_mode, out)
        } else if zh_has_dict {
            self.chinese
                .analyze(slice, offset_base, position_base, query_mode, out)
        } else {
            cjk_ngram::analyze(slice, offset_base, position_base, out)
        }
    }

    /// Canonical manifest for this analyzer configuration. Gates LMDB
    /// text-index compatibility (plan §4.2). The per-lang `dict` field is
    /// populated from each backend's `asset_manifest` so the manifest
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
            // Reflects what `dispatch_run` actually invokes Snowball on.
            // Arabic / Hebrew / Indic / SEA scripts route to `icu::analyze`,
            // which performs no stemming, so they are intentionally absent —
            // adding them would bind the manifest hash to a capability that
            // never fires and trigger false-positive reindex on stemmer
            // version bumps.
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
            ],
        }
    }
}

fn whichlang_eligible(class: ScriptClass) -> bool {
    // Eligibility describes scripts whose downstream analyzer can consume a
    // language hint. Some classes, such as Greek, normally resolve earlier via
    // `infer_from_script` and never reach the detector branch.
    match class {
        ScriptClass::Latin | ScriptClass::Cyrillic | ScriptClass::Greek | ScriptClass::Han => true,
        ScriptClass::Hebrew
        | ScriptClass::Arabic
        | ScriptClass::Hiragana
        | ScriptClass::Katakana
        | ScriptClass::Hangul
        | ScriptClass::Thai
        | ScriptClass::Lao
        | ScriptClass::Khmer
        | ScriptClass::Myanmar
        | ScriptClass::Devanagari
        | ScriptClass::Tamil
        | ScriptClass::Common
        | ScriptClass::Other => false,
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
mod tests;
