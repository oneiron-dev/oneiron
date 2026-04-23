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
//! bytes are mmapped by Sudachi; we hold an `Arc<JapaneseDictionary>` so
//! the analyzer is cheaply cloneable for per-thread use.
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
    /// mmapped and its bytes kept alive by the returned analyzer.
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
                    .overlay(),
                );
            }
        }

        // Mode C overlay: emit longer compound spans on NormalizedOverlay.
        // Suppressed in query_mode (plan §1.2 — overlays only inflate IDF).
        if !query_mode
            && let Ok(morphemes_c) = tokenizer.tokenize(text, Mode::C, false)
        {
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
                        .overlay(),
                    );
                }
            }
        }

        position_base + a_count as u32
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
mod tests {
    use super::*;

    #[test]
    fn portable_analyzer_has_portable_mode() {
        let ja = JapaneseAnalyzer::portable();
        assert_eq!(ja.mode(), AnalyzerMode::Portable);
        assert!(ja.dict_path().is_none());
    }

    #[test]
    fn discover_with_no_paths_returns_portable() {
        let ja = JapaneseAnalyzer::discover(&[]).unwrap();
        assert_eq!(ja.mode(), AnalyzerMode::Portable);
    }

    #[test]
    fn discover_with_empty_dir_returns_portable() {
        let dir = tempfile::tempdir().unwrap();
        let ja = JapaneseAnalyzer::discover(&[dir.path().to_path_buf()]).unwrap();
        assert_eq!(ja.mode(), AnalyzerMode::Portable);
    }

    #[test]
    fn portable_path_delegates_to_cjk_ngram() {
        let ja = JapaneseAnalyzer::portable();
        let mut out = Vec::new();
        ja.analyze("東京大学", 0, 0, false, &mut out);

        let surface: Vec<&str> = out
            .iter()
            .filter(|t| t.channel == AnalyzerChannel::Surface)
            .map(|t| t.term.as_ref())
            .collect();
        assert_eq!(surface, vec!["東", "京", "大", "学"]);

        let ngram: Vec<&str> = out
            .iter()
            .filter(|t| t.channel == AnalyzerChannel::CjkNgram)
            .map(|t| t.term.as_ref())
            .collect();
        assert_eq!(ngram, vec!["東京", "京大", "大学"]);
    }

    #[test]
    fn empty_input_returns_position_base() {
        let ja = JapaneseAnalyzer::portable();
        let mut out = Vec::new();
        let next = ja.analyze("", 0, 5, false, &mut out);
        assert_eq!(next, 5);
        assert!(out.is_empty());
    }

    #[test]
    fn kana_fold_if_changed_identifies_only_katakana_bearing_input() {
        assert!(kana_fold_if_changed("ひらがな").is_none());
        assert!(kana_fold_if_changed("ascii").is_none());
        assert_eq!(kana_fold_if_changed("カタカナ"), Some("かたかな".to_string()));
    }

    /// Morphological-mode integration: only runs when a real Sudachi dict is
    /// available via `ONEIRON_TEST_SUDACHI_DICT` (absolute path to `system.dic`).
    /// Not part of default `cargo test` because `system.dic` is ~12 MB and not
    /// bundled with the repo.
    #[test]
    fn morphological_path_with_env_dict() {
        let Ok(dict_path) = std::env::var("ONEIRON_TEST_SUDACHI_DICT") else {
            return;
        };
        let ja = JapaneseAnalyzer::with_system_dict(Path::new(&dict_path))
            .expect("dict should load");
        assert_eq!(ja.mode(), AnalyzerMode::Morphological);

        let mut out = Vec::new();
        ja.analyze("東京大学で研究する", 0, 0, false, &mut out);
        assert!(!out.is_empty());
        let surface: Vec<&str> = out
            .iter()
            .filter(|t| t.channel == AnalyzerChannel::Surface)
            .map(|t| t.term.as_ref())
            .collect();
        // Mode A should segment at least to 東京 / 大学 / で / 研究 / する boundaries.
        assert!(surface.contains(&"東京"));
        assert!(surface.contains(&"大学"));
    }

    /// Query-side kana-fold overlay must fire so katakana queries retrieve
    /// hiragana documents (fold is a symmetric normalization, not a lemma
    /// expansion). Uses the real Sudachi dict via `ONEIRON_TEST_SUDACHI_DICT`.
    #[test]
    fn kana_fold_overlay_fires_on_query() {
        let Ok(dict_path) = std::env::var("ONEIRON_TEST_SUDACHI_DICT") else {
            return;
        };
        let ja = JapaneseAnalyzer::with_system_dict(Path::new(&dict_path))
            .expect("dict should load");
        let mut out = Vec::new();
        ja.analyze("トウキョウ", 0, 0, /* query_mode */ true, &mut out);
        let overlay_terms: Vec<&str> = out
            .iter()
            .filter(|t| t.channel == AnalyzerChannel::NormalizedOverlay)
            .map(|t| t.term.as_ref())
            .collect();
        assert!(
            !overlay_terms.is_empty(),
            "katakana query must emit at least one kana-folded overlay",
        );
        for term in &overlay_terms {
            assert!(
                !term.chars().any(|c| ('\u{30A0}'..='\u{30FF}').contains(&c)),
                "overlay {term:?} still contains katakana — fold did not run",
            );
        }
    }
}
