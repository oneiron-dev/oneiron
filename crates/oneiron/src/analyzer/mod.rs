//! Multilingual analyzer subsystem.
//!
//! Scaffold for ONE-317. This commit lands the public token, channel,
//! context, and manifest types plus a canonical-JSON hasher. Analyzer
//! implementations (normalization, script splitter, language detection,
//! per-script analyzers, composer) land in subsequent commits.

pub mod cjk_ngram;
pub mod detect;
pub mod latin;
pub mod manifest;
pub mod normalize;
pub mod script;
pub mod token;

pub use manifest::{
    ANALYZER_VERSION, AnalyzerAssetManifest, AnalyzerManifest, AnalyzerMode, LangPolicy,
    NormalizationPolicy, canonical_hash, canonical_hash_hex, canonical_json,
};
pub use detect::{DETECT_WINDOW_BYTES, PerDocCache};
pub use script::{ScriptClass, ScriptRun, ScriptRunSplitter};
pub use token::{AnalyzerChannel, AnalyzerContext, LanguageHint, Token, TokenKind};
