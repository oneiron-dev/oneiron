//! Multilingual analyzer subsystem. Defined in `oneiron-retrieval`; every
//! `oneiron::analyzer` path is unchanged.

pub use oneiron_retrieval::analyzer::{
    ANALYZER_VERSION, AnalyzerAssetManifest, AnalyzerChannel, AnalyzerContext, AnalyzerManifest,
    AnalyzerMode, DETECT_WINDOW_BYTES, DiscoverError, LangPolicy, LanguageHint,
    MultilingualAnalyzer, NormalizationPolicy, NormalizedText, ScriptClass, ScriptRun,
    ScriptRunSplitter, Token, TokenKind, canonical_hash, canonical_hash_hex, canonical_json,
    chinese, cjk_ngram, detect, icu, japanese, korean, latin, manifest, normalize, script, token,
};
