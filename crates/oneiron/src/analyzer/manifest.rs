//! Analyzer + asset manifest types, plus the canonical-JSON hasher that
//! gates LMDB text-index compatibility.
//!
//! Canonical JSON here is `serde_json` output over struct-typed values with
//! `BTreeMap` for every map field. Struct fields serialize in declaration
//! order; `BTreeMap` iterates in lexicographic key order; no floats appear
//! in the payload. That gives a stable byte representation suitable for
//! sha256 hashing without pulling in a dedicated canonical-JSON crate.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const ANALYZER_VERSION: &str = "v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalyzerManifest {
    pub analyzer_version: String,
    pub normalization: NormalizationPolicy,
    pub langs: BTreeMap<String, LangPolicy>,
    pub channels: Vec<String>,
    pub stemmer_langs: Vec<String>,
}

impl AnalyzerManifest {
    pub fn canonical_json(&self) -> Result<String, serde_json::Error> {
        canonical_json(self)
    }

    pub fn canonical_hash(&self) -> Result<[u8; 32], serde_json::Error> {
        canonical_hash(self)
    }

    pub fn canonical_hash_hex(&self) -> Result<String, serde_json::Error> {
        canonical_hash_hex(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizationPolicy {
    pub nfkc: bool,
    pub casefold: bool,
    pub width_fold: bool,
    pub kana_fold: bool,
}

impl Default for NormalizationPolicy {
    fn default() -> Self {
        Self {
            nfkc: true,
            casefold: true,
            width_fold: true,
            kana_fold: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LangPolicy {
    pub mode: AnalyzerMode,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub dict: Option<AnalyzerAssetManifest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AnalyzerMode {
    Morphological,
    Portable,
}

impl AnalyzerMode {
    /// Stable machine identifier. Matches the serde-serialized form so
    /// round-tripping the manifest never changes mode strings.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Morphological => "morphological",
            Self::Portable => "portable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalyzerAssetManifest {
    pub name: String,
    pub version: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub license: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub source: Option<String>,
}

pub fn canonical_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    serde_json::to_string(value)
}

pub fn canonical_hash<T: Serialize>(value: &T) -> Result<[u8; 32], serde_json::Error> {
    let json = canonical_json(value)?;
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    Ok(hasher.finalize().into())
}

pub fn canonical_hash_hex<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let bytes = canonical_hash(value)?;
    Ok(hex_encode(&bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest() -> AnalyzerManifest {
        let mut langs = BTreeMap::new();
        langs.insert(
            "ja".to_string(),
            LangPolicy {
                mode: AnalyzerMode::Morphological,
                dict: Some(AnalyzerAssetManifest {
                    name: "SudachiDict-core".to_string(),
                    version: "20250403".to_string(),
                    sha256: "a".repeat(64),
                    size_bytes: 73_400_320,
                    license: "Apache-2.0".to_string(),
                    source: Some("https://github.com/WorksApplications/SudachiDict".to_string()),
                }),
            },
        );
        langs.insert(
            "*".to_string(),
            LangPolicy {
                mode: AnalyzerMode::Portable,
                dict: None,
            },
        );
        AnalyzerManifest {
            analyzer_version: ANALYZER_VERSION.to_string(),
            normalization: NormalizationPolicy::default(),
            langs,
            channels: AnalyzerChannelList::v1(),
            stemmer_langs: vec!["en".into(), "es".into()],
        }
    }

    struct AnalyzerChannelList;
    impl AnalyzerChannelList {
        fn v1() -> Vec<String> {
            vec![
                "surface".into(),
                "stem".into(),
                "normalized_overlay".into(),
                "cjk_ngram".into(),
            ]
        }
    }

    #[test]
    fn canonical_json_sorts_lang_keys() {
        let m = sample_manifest();
        let json = m.canonical_json().unwrap();
        let star = json.find("\"*\"").unwrap();
        let ja = json.find("\"ja\"").unwrap();
        assert!(star < ja, "BTreeMap must emit '*' before 'ja'");
    }

    #[test]
    fn canonical_hash_is_stable_across_calls() {
        let m = sample_manifest();
        let h1 = m.canonical_hash().unwrap();
        let h2 = m.canonical_hash().unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn canonical_hash_changes_when_manifest_changes() {
        let mut m = sample_manifest();
        let h1 = m.canonical_hash().unwrap();
        m.langs.insert(
            "ko".to_string(),
            LangPolicy {
                mode: AnalyzerMode::Morphological,
                dict: None,
            },
        );
        let h2 = m.canonical_hash().unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn canonical_hash_hex_is_64_chars() {
        let m = sample_manifest();
        let hex = m.canonical_hash_hex().unwrap();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn analyzer_mode_serializes_lowercase() {
        let morph = serde_json::to_string(&AnalyzerMode::Morphological).unwrap();
        let portable = serde_json::to_string(&AnalyzerMode::Portable).unwrap();
        assert_eq!(morph, "\"morphological\"");
        assert_eq!(portable, "\"portable\"");
    }

    #[test]
    fn manifest_roundtrips_through_serde() {
        let m = sample_manifest();
        let json = serde_json::to_string(&m).unwrap();
        let back: AnalyzerManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn normalization_policy_default_enables_all() {
        let n = NormalizationPolicy::default();
        assert!(n.nfkc && n.casefold && n.width_fold && n.kana_fold);
    }

    #[test]
    fn asset_manifest_skips_none_source() {
        let asset = AnalyzerAssetManifest {
            name: "x".into(),
            version: "1".into(),
            sha256: "0".repeat(64),
            size_bytes: 0,
            license: "MIT".into(),
            source: None,
        };
        let json = serde_json::to_string(&asset).unwrap();
        assert!(!json.contains("source"));
    }
}
