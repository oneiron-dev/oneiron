//! Korean analyzer.
//!
//! Per plan §7: Lindera morphological segmentation (via mecab-ko-dic) when
//! a `<path>/ko/` dict directory is discoverable, with a Hangul syllable
//! bigram overlay on the `CjkNgram` channel. When no dict is discoverable
//! (Portable mode), defers to [`cjk_ngram::analyze`].
//!
//! mecab-ko-dic data is Apache-2.0 — the default Korean dict bundle per
//! plan §2.3. Lindera exposes the segmenter with byte offsets, so no
//! char→byte translation is needed (contrast with jieba-rs).

use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use lindera::dictionary::{Dictionary, load_fs_dictionary};
use lindera::mode::Mode;
use lindera::segmenter::Segmenter;

use super::cjk_ngram;
use super::manifest::{AnalyzerAssetManifest, AnalyzerMode};
use super::token::{AnalyzerChannel, Token, TokenKind};

pub const DICT_SUBDIR: &str = "ko";
/// Characteristic file that signals a loadable Lindera dict directory.
pub const DICT_MARKER: &str = "metadata.json";
/// Asset identity recorded in the manifest when a KO dict is loaded.
/// Fingerprinting is performed over every regular file in the dict
/// directory (via [`AnalyzerAssetManifest::probe_directory`]) so the
/// vault manifest hash binds to the exact bytes Lindera ingested, not
/// just to `metadata.json`.
const KO_ASSET_NAME: &str = "mecab-ko-dic";
const KO_ASSET_LICENSE: &str = "Apache-2.0";
const KO_ASSET_SOURCE: &str = "https://bitbucket.org/eunjeon/mecab-ko-dic";

/// Korean analyzer. Cheaply cloneable — Segmenter is held in `Arc`.
#[derive(Clone)]
pub struct KoreanAnalyzer {
    segmenter: Option<Arc<Segmenter>>,
    dict_path: Option<PathBuf>,
    asset: Option<AnalyzerAssetManifest>,
}

impl std::fmt::Debug for KoreanAnalyzer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KoreanAnalyzer")
            .field("mode", &self.mode())
            .field("dict_path", &self.dict_path)
            .finish()
    }
}

impl KoreanAnalyzer {
    /// Analyzer with no dict — Portable path only.
    pub fn portable() -> Self {
        Self {
            segmenter: None,
            dict_path: None,
            asset: None,
        }
    }

    /// Walk `search_paths` in order and load the first `<path>/ko/` directory
    /// that looks like a Lindera dict (contains `metadata.json`). Returns
    /// Portable if none found.
    pub fn discover(search_paths: &[PathBuf]) -> Result<Self, DictLoadError> {
        for root in search_paths {
            let candidate = root.join(DICT_SUBDIR);
            if candidate.is_dir() && candidate.join(DICT_MARKER).is_file() {
                return Self::with_dict_dir(&candidate);
            }
        }
        Ok(Self::portable())
    }

    /// Build a Korean analyzer around a specific Lindera dict directory.
    pub fn with_dict_dir(path: &Path) -> Result<Self, DictLoadError> {
        let dictionary: Dictionary =
            load_fs_dictionary(path).map_err(|e| DictLoadError::Lindera {
                path: path.to_path_buf(),
                source: Box::new(e),
            })?;
        let segmenter = Segmenter::new(Mode::Normal, dictionary, None);
        let asset = AnalyzerAssetManifest::probe_directory(
            KO_ASSET_NAME,
            "unknown",
            KO_ASSET_LICENSE,
            Some(KO_ASSET_SOURCE.to_string()),
            path,
        )
        .map_err(|e| DictLoadError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        Ok(Self {
            segmenter: Some(Arc::new(segmenter)),
            dict_path: Some(path.to_path_buf()),
            asset: Some(asset),
        })
    }

    pub fn mode(&self) -> AnalyzerMode {
        if self.segmenter.is_some() {
            AnalyzerMode::Morphological
        } else {
            AnalyzerMode::Portable
        }
    }

    pub fn dict_path(&self) -> Option<&Path> {
        self.dict_path.as_deref()
    }

    /// Fingerprint of the currently-loaded ko-dic metadata, or None in
    /// Portable mode. Binds the LMDB text-index hash to the dict identity.
    pub fn asset_manifest(&self) -> Option<&AnalyzerAssetManifest> {
        self.asset.as_ref()
    }

    /// Analyze `text` as Korean and append tokens to `out`.
    ///
    /// Morphological path (dict present):
    /// * Lindera morphemes → `Surface` tokens at positions 0..N
    /// * Hangul syllable bigrams → `CjkNgram` overlay tokens
    ///
    /// Portable path (no dict): delegates to [`cjk_ngram::analyze`].
    pub fn analyze(
        &self,
        text: &str,
        offset_base: u32,
        position_base: u32,
        _query_mode: bool,
        out: &mut Vec<Token>,
    ) -> u32 {
        // `query_mode` is intentionally ignored for the CjkNgram overlay;
        // see the Chinese analyzer's morphological path for rationale
        // (same decision, same channel).
        if text.is_empty() {
            return position_base;
        }
        match self.segmenter.as_ref() {
            None => cjk_ngram::analyze(text, offset_base, position_base, out),
            Some(seg) => self.analyze_morphological(seg, text, offset_base, position_base, out),
        }
    }

    fn analyze_morphological(
        &self,
        seg: &Segmenter,
        text: &str,
        offset_base: u32,
        position_base: u32,
        out: &mut Vec<Token>,
    ) -> u32 {
        let Ok(tokens) = seg.segment(Cow::Borrowed(text)) else {
            return cjk_ngram::analyze(text, offset_base, position_base, out);
        };

        let mut position = position_base;
        for t in tokens {
            let start = offset_base + t.byte_start as u32;
            let end = offset_base + t.byte_end as u32;
            out.push(Token::new(
                t.surface.into_owned(),
                start,
                end,
                position,
                AnalyzerChannel::Surface,
                TokenKind::Cjk,
            ));
            position += 1;
        }

        cjk_ngram::emit_bigram_overlay(text, offset_base, position_base, out);

        let morph_count = position - position_base;
        let bigram_count = (text.chars().count() as u32).saturating_sub(1);
        position_base + morph_count.max(bigram_count)
    }
}

/// Errors returned when a Korean dictionary directory cannot be loaded.
#[derive(Debug, thiserror::Error)]
pub enum DictLoadError {
    #[error("lindera rejected KO dictionary at {path:?}: {source}")]
    Lindera {
        path: PathBuf,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("failed to read KO dictionary file at {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_with_no_paths_returns_portable() {
        let ko = KoreanAnalyzer::discover(&[]).unwrap();
        assert_eq!(ko.mode(), AnalyzerMode::Portable);
    }

    #[test]
    fn discover_with_empty_dir_returns_portable() {
        let dir = tempfile::tempdir().unwrap();
        let ko = KoreanAnalyzer::discover(&[dir.path().to_path_buf()]).unwrap();
        assert_eq!(ko.mode(), AnalyzerMode::Portable);
    }

    #[test]
    fn discover_dir_without_marker_returns_portable() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("ko")).unwrap();
        let ko = KoreanAnalyzer::discover(&[dir.path().to_path_buf()]).unwrap();
        assert_eq!(ko.mode(), AnalyzerMode::Portable);
    }

    #[test]
    fn portable_path_delegates_to_cjk_ngram() {
        let ko = KoreanAnalyzer::portable();
        let mut out = Vec::new();
        ko.analyze("안녕하세요", 0, 0, false, &mut out);
        let surface: Vec<&str> = out
            .iter()
            .filter(|t| t.channel == AnalyzerChannel::Surface)
            .map(|t| t.term.as_ref())
            .collect();
        assert_eq!(surface, vec!["안", "녕", "하", "세", "요"]);
    }

    #[test]
    fn empty_input_returns_position_base() {
        let ko = KoreanAnalyzer::portable();
        let mut out = Vec::new();
        let next = ko.analyze("", 0, 7, false, &mut out);
        assert_eq!(next, 7);
        assert!(out.is_empty());
    }

    /// Morphological-mode integration: only runs when a ko-dic dict
    /// directory is available via `ONEIRON_TEST_KODIC_DIR` (absolute path).
    #[test]
    fn morphological_path_with_env_dict() {
        let Ok(dict_path) = std::env::var("ONEIRON_TEST_KODIC_DIR") else {
            return;
        };
        let ko = KoreanAnalyzer::with_dict_dir(Path::new(&dict_path)).expect("ko-dic should load");
        assert_eq!(ko.mode(), AnalyzerMode::Morphological);

        let mut out = Vec::new();
        ko.analyze("한국어는 재미있어요", 0, 0, false, &mut out);
        assert!(!out.is_empty());
        for tok in out.iter().filter(|t| t.channel == AnalyzerChannel::Surface) {
            let slice = &"한국어는 재미있어요"[tok.byte_start as usize..tok.byte_end as usize];
            assert_eq!(slice, tok.term.as_ref());
        }
    }

    #[test]
    fn ko_morph_returns_position_past_bigram_overlay() {
        let Ok(dict_path) = std::env::var("ONEIRON_TEST_KODIC_DIR") else {
            return;
        };
        let ko = KoreanAnalyzer::with_dict_dir(Path::new(&dict_path)).expect("ko-dic should load");
        let text = "대한민국";
        let mut out = Vec::new();
        let next = ko.analyze(text, 0, 0, false, &mut out);
        let surface_count = out
            .iter()
            .filter(|t| t.channel == AnalyzerChannel::Surface)
            .count() as u32;
        let bigram_count = (text.chars().count() as u32).saturating_sub(1);
        if surface_count >= bigram_count {
            return;
        }
        let max_emitted = out.iter().map(|t| t.position).max().unwrap_or(0);
        assert!(
            next > max_emitted,
            "Korean analyzer returned {next} but emitted token at position {max_emitted}",
        );
    }
}
