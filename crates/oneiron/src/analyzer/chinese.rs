//! Chinese analyzer.
//!
//! Per plan §7: jieba-rs search-mode segmentation when a user-supplied
//! jieba dict is discoverable (plan §2.3 disallows shipping a default
//! Chinese dict — license constraints), with a Han bigram overlay on the
//! `CjkNgram` channel. When no dict is discoverable (Portable mode),
//! defers to [`cjk_ngram::analyze`] so Chinese text still tokenizes.
//!
//! jieba emits tokens with **character** (code-point) positions. Plan §3.3
//! requires a char→byte table per field so our emitted tokens always have
//! byte-accurate `byte_start` / `byte_end` into the caller's original UTF-8.
//! This is what [`char_to_byte_table`] and the `analyze_morphological`
//! function build and consume.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use jieba_rs::{Jieba, Token as JiebaToken, TokenizeMode};

use super::cjk_ngram;
use super::manifest::{AnalyzerAssetManifest, AnalyzerMode};
use super::token::{AnalyzerChannel, Token, TokenKind};

pub const DICT_FILENAME: &str = "jieba.dict.utf8";
pub const DICT_SUBDIR: &str = "zh";
/// Identity recorded in the manifest when a Chinese dict is loaded. The
/// license is "user-supplied" on purpose — plan §2.3 disallows shipping a
/// default ZH dict, so the asset-policy gate (tests/analyzer_asset_policy.rs)
/// treats any discovered ZH asset as a soft warning, not a hard allow.
const ZH_ASSET_NAME: &str = "jieba-user-dict";
const ZH_ASSET_LICENSE: &str = "user-supplied";

/// Chinese analyzer. Cheaply cloneable — internal Jieba is `Arc`-shared.
#[derive(Clone)]
pub struct ChineseAnalyzer {
    jieba: Option<Arc<Jieba>>,
    dict_path: Option<PathBuf>,
    asset: Option<AnalyzerAssetManifest>,
}

impl std::fmt::Debug for ChineseAnalyzer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChineseAnalyzer")
            .field("mode", &self.mode())
            .field("dict_path", &self.dict_path)
            .finish()
    }
}

impl ChineseAnalyzer {
    /// Analyzer with no dict — Portable path only.
    pub fn portable() -> Self {
        Self {
            jieba: None,
            dict_path: None,
            asset: None,
        }
    }

    /// Walk `search_paths` in order and load the first
    /// `<path>/zh/jieba.dict.utf8` found. Returns Portable if none.
    pub fn discover(search_paths: &[PathBuf]) -> Result<Self, DictLoadError> {
        for root in search_paths {
            let candidate = root.join(DICT_SUBDIR).join(DICT_FILENAME);
            if candidate.is_file() {
                return Self::with_dict(&candidate);
            }
        }
        Ok(Self::portable())
    }

    /// Build a Chinese analyzer around a specific jieba dict file.
    pub fn with_dict(path: &Path) -> Result<Self, DictLoadError> {
        let file = std::fs::File::open(path).map_err(|e| DictLoadError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        let mut reader = std::io::BufReader::new(file);
        let jieba = Jieba::with_dict(&mut reader).map_err(|e| DictLoadError::Jieba {
            path: path.to_path_buf(),
            source: Box::new(e),
        })?;
        let asset = AnalyzerAssetManifest::probe_file(
            ZH_ASSET_NAME,
            "unknown",
            ZH_ASSET_LICENSE,
            None,
            path,
        )
        .map_err(|e| DictLoadError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        Ok(Self {
            jieba: Some(Arc::new(jieba)),
            dict_path: Some(path.to_path_buf()),
            asset: Some(asset),
        })
    }

    pub fn mode(&self) -> AnalyzerMode {
        if self.jieba.is_some() {
            AnalyzerMode::Morphological
        } else {
            AnalyzerMode::Portable
        }
    }

    pub fn dict_path(&self) -> Option<&Path> {
        self.dict_path.as_deref()
    }

    /// Fingerprint of the currently-loaded jieba dict, or None in Portable
    /// mode. Wired into the analyzer manifest so the LMDB text-index hash
    /// binds to the exact dict bytes.
    pub fn asset_manifest(&self) -> Option<&AnalyzerAssetManifest> {
        self.asset.as_ref()
    }

    /// Analyze `text` as Chinese and append tokens to `out`.
    ///
    /// Morphological path (dict present):
    /// * jieba search-mode words → `Surface` tokens at positions 0..N
    /// * script-safe Han character bigrams → `CjkNgram` overlay tokens
    ///   (always emitted regardless of morphological mode per plan §7)
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
        match self.jieba.as_ref() {
            None => cjk_ngram::analyze(text, offset_base, position_base, out),
            Some(jieba) => {
                self.analyze_morphological(jieba, text, offset_base, position_base, query_mode, out)
            }
        }
    }

    fn analyze_morphological(
        &self,
        jieba: &Jieba,
        text: &str,
        offset_base: u32,
        position_base: u32,
        query_mode: bool,
        out: &mut Vec<Token>,
    ) -> u32 {
        let c2b = char_to_byte_table(text);
        let jtokens: Vec<JiebaToken<'_>> = jieba.tokenize(text, TokenizeMode::Search, true);

        let mut position = position_base;
        for t in jtokens.iter() {
            let start = offset_base + c2b.byte_of_char(t.start) as u32;
            let end = offset_base + c2b.byte_of_char(t.end) as u32;
            out.push(Token::new(
                t.word,
                start,
                end,
                position,
                AnalyzerChannel::Surface,
                TokenKind::Cjk,
            ));
            position += 1;
        }

        // Character bigram overlay — emit regardless of query_mode. CjkNgram
        // is the generated-ngram channel and a query like "京大" needs to
        // hit the bigram channel to recall docs indexed via jieba-segmented
        // "東京大学". Its contribution is additive across docs, not an IDF
        // inflation risk for the same doc.
        let _ = query_mode;
        cjk_ngram::emit_bigram_overlay(text, offset_base, position_base, out);

        let morph_count = position - position_base;
        let bigram_count = (c2b.char_count() as u32).saturating_sub(1);
        position_base + morph_count.max(bigram_count)
    }
}

/// Precomputed translation between UTF-8 byte offsets and char (code point)
/// indices. Built once per text slice and consulted whenever jieba-emitted
/// character positions need to be mapped back to byte offsets (plan §3.3).
pub struct CharByteTable {
    /// `byte_of_char[i]` = byte offset of the i-th char start.
    /// Length = char_count + 1 (last entry = input byte length).
    byte_of_char: Vec<usize>,
}

impl CharByteTable {
    pub fn byte_of_char(&self, char_idx: usize) -> usize {
        self.byte_of_char[char_idx]
    }

    pub fn char_count(&self) -> usize {
        self.byte_of_char.len().saturating_sub(1)
    }
}

pub fn char_to_byte_table(text: &str) -> CharByteTable {
    let mut byte_of_char: Vec<usize> = Vec::with_capacity(text.len() + 1);
    for (b, _) in text.char_indices() {
        byte_of_char.push(b);
    }
    byte_of_char.push(text.len());
    CharByteTable { byte_of_char }
}

/// Errors returned when a Chinese dictionary file cannot be loaded.
#[derive(Debug, thiserror::Error)]
pub enum DictLoadError {
    #[error("failed to read ZH dictionary at {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("jieba rejected ZH dictionary at {path:?}: {source}")]
    Jieba {
        path: PathBuf,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_with_no_paths_returns_portable() {
        let zh = ChineseAnalyzer::discover(&[]).unwrap();
        assert_eq!(zh.mode(), AnalyzerMode::Portable);
    }

    #[test]
    fn discover_with_empty_dir_returns_portable() {
        let dir = tempfile::tempdir().unwrap();
        let zh = ChineseAnalyzer::discover(&[dir.path().to_path_buf()]).unwrap();
        assert_eq!(zh.mode(), AnalyzerMode::Portable);
    }

    #[test]
    fn portable_path_delegates_to_cjk_ngram() {
        let zh = ChineseAnalyzer::portable();
        let mut out = Vec::new();
        zh.analyze("我爱北京", 0, 0, false, &mut out);
        let surface: Vec<&str> = out
            .iter()
            .filter(|t| t.channel == AnalyzerChannel::Surface)
            .map(|t| t.term.as_ref())
            .collect();
        assert_eq!(surface, vec!["我", "爱", "北", "京"]);
    }

    #[test]
    fn empty_input_returns_position_base() {
        let zh = ChineseAnalyzer::portable();
        let mut out = Vec::new();
        let next = zh.analyze("", 0, 3, false, &mut out);
        assert_eq!(next, 3);
        assert!(out.is_empty());
    }

    /// `char_to_byte_table` must round-trip char index → byte offset across
    /// multibyte, pure-ASCII, and empty inputs.
    ///
    /// Variants:
    /// - `multibyte`: `"a北b京"` mixes 1- and 3-byte chars.
    /// - `ascii_only`: `"hello"` — char index equals byte index.
    /// - `empty`: `""` — zero chars, `byte_of_char(0) == 0`.
    #[test]
    fn char_to_byte_roundtrip_multibyte() {
        // multibyte
        {
            let text = "a北b京";
            let t = char_to_byte_table(text);
            assert_eq!(t.char_count(), 4, "case multibyte: char_count");
            assert_eq!(t.byte_of_char(0), 0, "case multibyte: char 0");
            assert_eq!(t.byte_of_char(1), 1, "case multibyte: char 1 after 'a'");
            assert_eq!(
                t.byte_of_char(2),
                4,
                "case multibyte: char 2 after '北' (3 bytes)"
            );
            assert_eq!(t.byte_of_char(3), 5, "case multibyte: char 3 after 'b'");
            assert_eq!(t.byte_of_char(4), 8, "case multibyte: char 4 after '京'");
        }

        // ascii_only
        {
            let t = char_to_byte_table("hello");
            assert_eq!(t.char_count(), 5, "case ascii_only: char_count");
            for i in 0..=5 {
                assert_eq!(t.byte_of_char(i), i, "case ascii_only: char {i}");
            }
        }

        // empty
        {
            let t = char_to_byte_table("");
            assert_eq!(t.char_count(), 0, "case empty: char_count");
            assert_eq!(t.byte_of_char(0), 0, "case empty: char 0");
        }
    }

    /// Morphological-mode integration: only runs when a jieba dict file is
    /// available via `ONEIRON_TEST_JIEBA_DICT` (absolute path).
    #[test]
    fn morphological_path_with_env_dict() {
        let Ok(dict_path) = std::env::var("ONEIRON_TEST_JIEBA_DICT") else {
            return;
        };
        let zh = ChineseAnalyzer::with_dict(Path::new(&dict_path)).expect("dict should load");
        assert_eq!(zh.mode(), AnalyzerMode::Morphological);

        let mut out = Vec::new();
        zh.analyze("我爱北京天安门", 0, 0, false, &mut out);
        assert!(!out.is_empty());
        // Expect at least one Surface token with byte offsets that slice
        // back into the original text validly.
        for tok in &out {
            let slice = &"我爱北京天安门"[tok.byte_start as usize..tok.byte_end as usize];
            assert_eq!(slice, tok.term.as_ref());
        }
    }

    #[test]
    fn zh_morph_returns_position_past_bigram_overlay() {
        let Ok(dict_path) = std::env::var("ONEIRON_TEST_JIEBA_DICT") else {
            return;
        };
        let zh = ChineseAnalyzer::with_dict(Path::new(&dict_path)).expect("dict should load");
        let text = "中华人民共和国";
        let mut out = Vec::new();
        let next = zh.analyze(text, 0, 0, false, &mut out);
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
            "Chinese analyzer returned {next} but emitted token at position {max_emitted}",
        );
    }
}
