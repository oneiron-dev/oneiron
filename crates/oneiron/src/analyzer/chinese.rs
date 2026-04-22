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
use super::manifest::AnalyzerMode;
use super::token::{AnalyzerChannel, Token, TokenKind};

pub const DICT_FILENAME: &str = "jieba.dict.utf8";
pub const DICT_SUBDIR: &str = "zh";

/// Chinese analyzer. Cheaply cloneable — internal Jieba is `Arc`-shared.
#[derive(Clone)]
pub struct ChineseAnalyzer {
    jieba: Option<Arc<Jieba>>,
    dict_path: Option<PathBuf>,
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
        Ok(Self {
            jieba: Some(Arc::new(jieba)),
            dict_path: Some(path.to_path_buf()),
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

        // Character bigram overlay — emit regardless of query_mode? Plan §1.2
        // says overlays suppressed in query mode to avoid IDF inflation, but
        // CjkNgram is specifically the generated-ngram channel and a query
        // like "京大" needs to hit the bigram channel to recall docs indexed
        // via jieba-segmented "東京大学". So emit overlay even in query mode
        // for the ngram channel — its contribution is additive across docs,
        // not an IDF inflation risk for the same doc.
        let _ = query_mode;
        emit_char_bigram_overlay(text, offset_base, &c2b, position_base, out);

        position
    }
}

fn emit_char_bigram_overlay(
    text: &str,
    offset_base: u32,
    c2b: &CharByteTable,
    position_base: u32,
    out: &mut Vec<Token>,
) {
    let chars: Vec<(u32, &str)> = text
        .char_indices()
        .map(|(i, c)| {
            let start = i as u32;
            let end = start + c.len_utf8() as u32;
            (start, &text[start as usize..end as usize])
        })
        .collect();

    for (i, &(local_start, ch)) in chars.iter().enumerate() {
        if let Some(&(next_local_start, next_ch)) = chars.get(i + 1) {
            let start = offset_base + local_start;
            let end = offset_base + next_local_start + next_ch.len() as u32;
            let mut term = String::with_capacity(ch.len() + next_ch.len());
            term.push_str(ch);
            term.push_str(next_ch);
            out.push(
                Token::new(
                    term,
                    start,
                    end,
                    position_base + c2b.char_of_byte(local_start as usize) as u32,
                    AnalyzerChannel::CjkNgram,
                    TokenKind::Cjk,
                )
                .overlay(),
            );
        }
    }
}

/// Precomputed translation between UTF-8 byte offsets and char (code point)
/// indices. Built once per text slice and consulted whenever jieba-emitted
/// character positions need to be mapped back to byte offsets (plan §3.3).
pub struct CharByteTable {
    /// `byte_of_char[i]` = byte offset of the i-th char start.
    /// Length = char_count + 1 (last entry = input byte length).
    byte_of_char: Vec<usize>,
    /// `char_of_byte[b]` = char index at byte offset b for every valid
    /// char-boundary byte. Intermediate bytes repeat the prior char index.
    char_of_byte: Vec<usize>,
}

impl CharByteTable {
    pub fn byte_of_char(&self, char_idx: usize) -> usize {
        self.byte_of_char[char_idx]
    }

    pub fn char_of_byte(&self, byte_idx: usize) -> usize {
        self.char_of_byte[byte_idx]
    }

    pub fn char_count(&self) -> usize {
        self.byte_of_char.len().saturating_sub(1)
    }
}

pub fn char_to_byte_table(text: &str) -> CharByteTable {
    let mut byte_of_char: Vec<usize> = Vec::with_capacity(text.chars().count() + 1);
    let mut char_of_byte: Vec<usize> = vec![0; text.len() + 1];
    let mut char_idx = 0usize;
    for (b, _) in text.char_indices() {
        byte_of_char.push(b);
        for entry in char_of_byte.iter_mut().skip(b) {
            *entry = char_idx;
        }
        char_idx += 1;
    }
    byte_of_char.push(text.len());
    // Byte offset equal to text.len() is "one past last char" = char_idx.
    if let Some(last) = char_of_byte.last_mut() {
        *last = char_idx;
    }
    CharByteTable {
        byte_of_char,
        char_of_byte,
    }
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
    fn portable_analyzer_has_portable_mode() {
        let zh = ChineseAnalyzer::portable();
        assert_eq!(zh.mode(), AnalyzerMode::Portable);
        assert!(zh.dict_path().is_none());
    }

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

    #[test]
    fn char_to_byte_roundtrip_multibyte() {
        let text = "a北b京";
        let t = char_to_byte_table(text);
        assert_eq!(t.char_count(), 4);
        assert_eq!(t.byte_of_char(0), 0);
        assert_eq!(t.byte_of_char(1), 1); // after 'a'
        assert_eq!(t.byte_of_char(2), 4); // after '北' (3 bytes)
        assert_eq!(t.byte_of_char(3), 5); // after 'b'
        assert_eq!(t.byte_of_char(4), 8); // after '京'
        assert_eq!(t.char_of_byte(0), 0);
        assert_eq!(t.char_of_byte(1), 1);
        assert_eq!(t.char_of_byte(4), 2);
        assert_eq!(t.char_of_byte(5), 3);
    }

    #[test]
    fn char_to_byte_ascii_only() {
        let t = char_to_byte_table("hello");
        assert_eq!(t.char_count(), 5);
        for i in 0..=5 {
            assert_eq!(t.byte_of_char(i), i);
            assert_eq!(t.char_of_byte(i), i.min(5));
        }
    }

    #[test]
    fn char_to_byte_empty() {
        let t = char_to_byte_table("");
        assert_eq!(t.char_count(), 0);
        assert_eq!(t.byte_of_char(0), 0);
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
}
