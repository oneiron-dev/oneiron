//! Analyzer + asset manifest types, plus the canonical-JSON hasher that
//! gates LMDB text-index compatibility.
//!
//! Canonical JSON here is `serde_json` output over struct-typed values with
//! `BTreeMap` for every map field. Struct fields serialize in declaration
//! order; `BTreeMap` iterates in lexicographic key order; no floats appear
//! in the payload. That gives a stable byte representation suitable for
//! sha256 hashing without pulling in a dedicated canonical-JSON crate.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::types::bytes_to_hex_lower;

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

/// Normalization flags carried in the analyzer manifest. Every bit is honored
/// by [`super::normalize::apply_pretokenize`] / [`super::normalize::kana_fold_overlay`].
/// Toggling any flag changes the manifest hash and thus requires a reindex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizationPolicy {
    pub nfkc: bool,
    pub casefold: bool,
    pub kana_fold: bool,
}

impl Default for NormalizationPolicy {
    fn default() -> Self {
        Self {
            nfkc: true,
            casefold: true,
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

impl AnalyzerAssetManifest {
    /// Fingerprint a dict file at `path` into an [`AnalyzerAssetManifest`].
    /// Streams the file once to compute sha256 without allocating a second
    /// buffer of dict bytes. Fails only on IO errors; caller is responsible
    /// for filling in the name / version / license fields per dict identity.
    pub fn probe_file(
        name: impl Into<String>,
        version: impl Into<String>,
        license: impl Into<String>,
        source: Option<String>,
        path: &Path,
    ) -> io::Result<Self> {
        use std::fs::File;
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        // `sha2::Sha256` implements `io::Write`, so streaming the file
        // through `io::copy` lets libstd own buffering and the final byte
        // count. Avoids a separate `metadata()?.len()` syscall and the
        // TOCTOU window between stat and read.
        let size_bytes = io::copy(&mut file, &mut hasher)?;
        let digest: [u8; 32] = hasher.finalize().into();
        Ok(Self {
            name: name.into(),
            version: version.into(),
            sha256: bytes_to_hex_lower(&digest),
            size_bytes,
            license: license.into(),
            source,
        })
    }

    /// Fingerprint a whole dict *directory* by streaming every regular
    /// file, in sorted filename order, through a single sha256. Each file
    /// contributes its filename length, filename bytes, content, then
    /// content length — so reordering or swapping files always changes
    /// the digest. Used by [`super::korean::KoreanAnalyzer`] since Lindera
    /// loads a multi-file dict tree rather than a single binary blob.
    /// Subdirectories are not descended into (all current Lindera dicts
    /// are flat).
    pub fn probe_directory(
        name: impl Into<String>,
        version: impl Into<String>,
        license: impl Into<String>,
        source: Option<String>,
        dir: &Path,
    ) -> io::Result<Self> {
        use std::fs::File;
        let mut entries: Vec<(std::ffi::OsString, std::path::PathBuf)> = std::fs::read_dir(dir)?
            .filter_map(|r| r.ok())
            .filter_map(|e| {
                let ft = e.file_type().ok()?;
                if ft.is_file() {
                    Some((e.file_name(), e.path()))
                } else {
                    None
                }
            })
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        let mut hasher = Sha256::new();
        let mut size_bytes: u64 = 0;
        for (file_name, file_path) in &entries {
            let name_bytes = file_name.as_encoded_bytes();
            hasher.update((name_bytes.len() as u64).to_le_bytes());
            hasher.update(name_bytes);
            let mut file = File::open(file_path)?;
            // Frame is `name_len | name | content | content_len`. Hashing
            // the observed byte count after `io::copy` means a single
            // streaming read per file and no pre-read `metadata().len()` —
            // same stat syscall saved, plus no TOCTOU window to police.
            let copied = io::copy(&mut file, &mut hasher)?;
            hasher.update(copied.to_le_bytes());
            size_bytes = size_bytes.saturating_add(copied);
        }
        let digest: [u8; 32] = hasher.finalize().into();
        Ok(Self {
            name: name.into(),
            version: version.into(),
            sha256: bytes_to_hex_lower(&digest),
            size_bytes,
            license: license.into(),
            source,
        })
    }
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
    Ok(bytes_to_hex_lower(&bytes))
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
        assert!(n.nfkc && n.casefold && n.kana_fold);
    }

    #[test]
    fn probe_directory_matches_reference_hash_and_detects_swaps() {
        use std::fs::{File, write};
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        // Write in reverse-alphabetical creation order so the test
        // exercises the sort step rather than raw read_dir iteration.
        write(dir.path().join("b.bin"), b"second").unwrap();
        write(dir.path().join("a.bin"), b"first").unwrap();
        let probed =
            AnalyzerAssetManifest::probe_directory("d", "v", "Apache-2.0", None, dir.path())
                .unwrap();
        assert_eq!(probed.size_bytes, (b"first".len() + b"second".len()) as u64);

        // Reference digest: sorted order is a.bin, b.bin; frame each as
        // `name_len | name | content | content_len`. If the sort step were
        // dropped or the framing changed, this assertion would fail.
        let mut reference = Sha256::new();
        for (name, content) in [("a.bin", &b"first"[..]), ("b.bin", &b"second"[..])] {
            reference.update((name.len() as u64).to_le_bytes());
            reference.update(name.as_bytes());
            reference.update(content);
            reference.update((content.len() as u64).to_le_bytes());
        }
        let expected: [u8; 32] = reference.finalize().into();
        assert_eq!(probed.sha256, bytes_to_hex_lower(&expected));

        // Swapping file *contents* (same filenames) must change the hash.
        let mut f = File::create(dir.path().join("a.bin")).unwrap();
        f.write_all(b"FIRST").unwrap();
        drop(f);
        let mutated =
            AnalyzerAssetManifest::probe_directory("d", "v", "Apache-2.0", None, dir.path())
                .unwrap();
        assert_ne!(probed.sha256, mutated.sha256);
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
