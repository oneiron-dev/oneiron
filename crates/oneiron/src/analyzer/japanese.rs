//! Japanese analyzer.
//!
//! Per plan §7: Sudachi mode A as `Surface`, mode C as `NormalizedOverlay`
//! span for longer compounds, plus a kana-fold (katakana → hiragana)
//! overlay on `NormalizedOverlay`. When no JP dictionary is discoverable
//! (Portable mode), defers to [`cjk_ngram::analyze`] so callers always get
//! tokens regardless of dict presence.
//!
//! Dict discovery probes `<path>/ja/system.dic` across
//! `VaultConfig.dict_search_paths` at `Vault::open` (plan §2.3). Dict file
//! bytes are read into an owned buffer (`std::fs::read`) and handed to
//! Sudachi as `Storage::Owned`.
//!
//! Offsets in emitted tokens are always absolute byte offsets into the
//! caller's original UTF-8 (`offset_base + local`). Sudachi morphemes
//! report byte offsets into the input it was given, so the translation
//! is a single addition.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sudachi::analysis::Mode;
use sudachi::analysis::stateless_tokenizer::StatelessTokenizer;
use sudachi::analysis::{Tokenize, morpheme::Morpheme};
use sudachi::config::Config;
use sudachi::dic::dictionary::JapaneseDictionary;
use sudachi::dic::storage::SudachiDicData;

use super::cjk_ngram;
use super::manifest::{AnalyzerAssetManifest, AnalyzerMode};
use super::normalize::kana_fold;
use super::token::{AnalyzerChannel, Token, TokenKind};

/// Name of the system dictionary file that signals JP morphological support.
pub const DICT_FILENAME: &str = "system.dic";
/// Subdirectory under each dict-search path where the JP dict should live.
pub const DICT_SUBDIR: &str = "ja";
/// Asset identity used in the manifest when a JP dict is loaded. Version
/// is "unknown" because Sudachi binary dicts don't self-report a version
/// string; packagers override this at build time if stronger identity is
/// required (plan §2.3).
const JA_ASSET_NAME: &str = "SudachiDict";
const JA_ASSET_LICENSE: &str = "Apache-2.0";
const JA_ASSET_SOURCE: &str = "https://github.com/WorksApplications/SudachiDict";

/// Japanese analyzer. Cheaply cloneable — internal dict is `Arc`-shared.
#[derive(Clone)]
pub struct JapaneseAnalyzer {
    dict: Option<Arc<JapaneseDictionary>>,
    dict_path: Option<PathBuf>,
    asset: Option<AnalyzerAssetManifest>,
}

impl std::fmt::Debug for JapaneseAnalyzer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JapaneseAnalyzer")
            .field("mode", &self.mode())
            .field("dict_path", &self.dict_path)
            .finish()
    }
}

impl JapaneseAnalyzer {
    /// Analyzer with no dict — always runs the Portable (cjk_ngram) path.
    pub fn portable() -> Self {
        Self {
            dict: None,
            dict_path: None,
            asset: None,
        }
    }

    /// Walk `search_paths` in order and load the first `<path>/ja/system.dic`
    /// found. Returns a Portable analyzer if no dict is found on any path.
    pub fn discover(search_paths: &[PathBuf]) -> Result<Self, DictLoadError> {
        for root in search_paths {
            let candidate = root.join(DICT_SUBDIR).join(DICT_FILENAME);
            if candidate.is_file() {
                return Self::with_system_dict(&candidate);
            }
        }
        Ok(Self::portable())
    }

    /// Build an analyzer around a specific `system.dic` file. The file is
    /// read into an owned byte buffer that Sudachi keeps alive.
    pub fn with_system_dict(path: &Path) -> Result<Self, DictLoadError> {
        let bytes = std::fs::read(path).map_err(|e| DictLoadError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        let storage = SudachiDicData::new(sudachi::dic::storage::Storage::Owned(bytes));
        let cfg = Config::minimal_at(
            path.parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from(".")),
        );
        let dict = JapaneseDictionary::from_cfg_storage_with_embedded_chardef(&cfg, storage)
            .map_err(|e| DictLoadError::Sudachi {
                path: path.to_path_buf(),
                source: Box::new(e),
            })?;
        let asset = AnalyzerAssetManifest::probe_file(
            JA_ASSET_NAME,
            "unknown",
            JA_ASSET_LICENSE,
            Some(JA_ASSET_SOURCE.to_string()),
            path,
        )
        .map_err(|e| DictLoadError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        Ok(Self {
            dict: Some(Arc::new(dict)),
            dict_path: Some(path.to_path_buf()),
            asset: Some(asset),
        })
    }

    pub fn mode(&self) -> AnalyzerMode {
        if self.dict.is_some() {
            AnalyzerMode::Morphological
        } else {
            AnalyzerMode::Portable
        }
    }

    pub fn dict_path(&self) -> Option<&Path> {
        self.dict_path.as_deref()
    }

    /// Fingerprint of the currently-loaded dict, or None in Portable mode.
    /// Surfaced into [`super::manifest::AnalyzerManifest::langs`] so the
    /// LMDB manifest hash binds to the exact dict bytes.
    pub fn asset_manifest(&self) -> Option<&AnalyzerAssetManifest> {
        self.asset.as_ref()
    }

    /// Analyze `text` as Japanese and append tokens to `out`.
    ///
    /// Morphological path (dict present):
    /// * Mode A morphemes → `Surface` tokens with per-morpheme position
    /// * Mode C morphemes whose span covers more than one Mode A morpheme
    ///   → `NormalizedOverlay` at the Mode A position of the first covered
    ///   morpheme, with `position_increment = 0` and `length_increment = 0`
    /// * Any Surface token containing katakana → kana-folded overlay
    ///   on `NormalizedOverlay` at the same position
    ///
    /// Portable path (no dict): delegates to [`cjk_ngram::analyze`].
    pub fn analyze(
        &self,
        text: &str,
        offset_base: u32,
        position_base: u32,
        query_mode: bool,
        out: &mut Vec<Token>,
    ) -> u32 {
        if text.is_empty() {
            return position_base;
        }
        match self.dict.as_ref() {
            None => cjk_ngram::analyze(text, offset_base, position_base, out),
            Some(dict) => {
                self.analyze_morphological(dict, text, offset_base, position_base, query_mode, out)
            }
        }
    }

    fn analyze_morphological(
        &self,
        dict: &Arc<JapaneseDictionary>,
        text: &str,
        offset_base: u32,
        position_base: u32,
        query_mode: bool,
        out: &mut Vec<Token>,
    ) -> u32 {
        let tokenizer = StatelessTokenizer::new(Arc::clone(dict));
        let Ok(morphemes_a) = tokenizer.tokenize(text, Mode::A, false) else {
            return cjk_ngram::analyze(text, offset_base, position_base, out);
        };

        // Collect Mode A morpheme byte ranges for Mode C overlay matching.
        // Positions map 1:1 to Mode A morpheme indices. The `a_by_start`
        // map lets Mode C look up its covering Mode A morpheme in O(1).
        let a_count = morphemes_a.len();
        let mut a_ranges: Vec<(u32, u32)> = Vec::with_capacity(a_count);
        let mut a_by_start: HashMap<u32, usize> = HashMap::with_capacity(a_count);

        for i in 0..a_count {
            let m: Morpheme<'_, _> = morphemes_a.get(i);
            let start = offset_base + m.begin() as u32;
            let end = offset_base + m.end() as u32;
            let surface = m.surface().to_string();
            let position = position_base + i as u32;
            a_ranges.push((start, end));
            a_by_start.insert(start, i);

            out.push(Token::new(
                surface.clone(),
                start,
                end,
                position,
                AnalyzerChannel::Surface,
                TokenKind::Word,
            ));

            // Kana-fold overlay (katakana → hiragana) is a true
            // normalization: both index and query sides must emit the
            // same folded term for the posting to hit. Unlike the Mode C
            // compound overlay below, this does not inflate IDF because
            // the fold collapses existing surface tokens to a canonical
            // form rather than emitting additional lemmas.
            if let Some(folded) = kana_fold_if_changed(&surface) {
                out.push(
                    Token::new(
                        folded,
                        start,
                        end,
                        position,
                        AnalyzerChannel::NormalizedOverlay,
                        TokenKind::Word,
                    )
                    .overlay()
                    .with_length_increment(0),
                );
            }
        }

        // Mode C overlay: emit longer compound spans on NormalizedOverlay
        // on both index and query sides. Without the query-side emission a
        // query `"大阪大学"` would only yield Mode A tokens `[大阪, 大学]`
        // and never hit indexed Mode C compounds. The scorer dedupes query
        // terms per posting, so adding the compound is a recall boost, not
        // an IDF inflation risk.
        let _ = query_mode;
        if let Ok(morphemes_c) = tokenizer.tokenize(text, Mode::C, false) {
            for i in 0..morphemes_c.len() {
                let m: Morpheme<'_, _> = morphemes_c.get(i);
                let start = offset_base + m.begin() as u32;
                let end = offset_base + m.end() as u32;
                // Find the Mode A morpheme that begins at this start offset.
                let Some(&first_a_idx) = a_by_start.get(&start) else {
                    continue;
                };
                let (_, first_a_end) = a_ranges[first_a_idx];
                // Only emit when the Mode C span actually covers more than a
                // single Mode A morpheme — otherwise it's identical content.
                if end > first_a_end {
                    let surface = m.surface().to_string();
                    let position = position_base + first_a_idx as u32;
                    out.push(
                        Token::new(
                            surface,
                            start,
                            end,
                            position,
                            AnalyzerChannel::NormalizedOverlay,
                            TokenKind::Word,
                        )
                        .overlay()
                        .with_length_increment(0),
                    );
                }
            }
        }

        // CjkNgram overlay: char bigrams so `"東京"` recalls docs indexed
        // via Sudachi-segmented `"東京大学"`. Bigrams sit at char-index
        // positions, which can exceed `a_count` when Mode A produces
        // multi-char morphemes (`"東京大学"` → 2 morphemes, 3 bigrams at
        // positions 0..=2). The next unused position is therefore
        // `max(a_count, char_count - 1)` past `position_base`.
        cjk_ngram::emit_bigram_overlay(text, offset_base, position_base, out);

        let char_count = text.chars().count() as u32;
        position_base + std::cmp::max(a_count as u32, char_count.saturating_sub(1))
    }
}

fn kana_fold_if_changed(surface: &str) -> Option<String> {
    match kana_fold(surface) {
        std::borrow::Cow::Borrowed(_) => None,
        std::borrow::Cow::Owned(s) => Some(s),
    }
}

/// Errors returned when a JP dictionary file cannot be loaded.
#[derive(Debug, thiserror::Error)]
pub enum DictLoadError {
    #[error("failed to read JP dictionary at {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("sudachi rejected JP dictionary at {path:?}: {source}")]
    Sudachi {
        path: PathBuf,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

#[cfg(test)]
mod tests;
