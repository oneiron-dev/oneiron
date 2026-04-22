//! Multilingual analyzer subsystem.
//!
//! Scaffold for ONE-317. This commit lands the public token, channel,
//! context, and manifest types plus a canonical-JSON hasher. Analyzer
//! implementations (normalization, script splitter, language detection,
//! per-script analyzers, composer) land in subsequent commits.

pub mod manifest;
pub mod token;

pub use manifest::{
    ANALYZER_VERSION, AnalyzerAssetManifest, AnalyzerManifest, AnalyzerMode, LangPolicy,
    NormalizationPolicy, canonical_hash, canonical_hash_hex, canonical_json,
};
pub use token::{AnalyzerChannel, AnalyzerContext, LanguageHint, Token, TokenKind};
