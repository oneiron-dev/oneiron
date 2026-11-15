//! K-proof (oracle) for PLAN-UC-04 stage 1.4: the analyzer manifest hash keeps its bytes.
//!
//! `canonical_hash` moved onto the fingerprint crate's K door
//! (`purposes::retrieval::ANALYZER_MANIFEST`). The hash is stored beside the manifest JSON
//! in every text index, so it must give main's bytes for every manifest. `base` below is a
//! copy of main's body (`crates/oneiron-retrieval/src/analyzer/manifest.rs:204-213` at
//! ea1e495a6605); it differs from those lines only in its indentation.
//!
//! The manifest holds no float, so the fixture table has no NaN row.

use std::collections::BTreeMap;

use oneiron_retrieval::analyzer::{
    AnalyzerAssetManifest, AnalyzerManifest, AnalyzerMode, LangPolicy, MultilingualAnalyzer,
    NormalizationPolicy, canonical_hash, canonical_hash_hex, canonical_json,
};

mod base {
    use serde::Serialize;
    use sha2::{Digest, Sha256};

    pub fn canonical_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
        serde_json::to_string(value)
    }

    pub fn canonical_hash<T: Serialize>(value: &T) -> Result<[u8; 32], serde_json::Error> {
        let json = canonical_json(value)?;
        let mut hasher = Sha256::new();
        hasher.update(json.as_bytes());
        Ok(hasher.finalize().into())
    }
}

fn asset(size_bytes: u64, source: Option<&str>) -> AnalyzerAssetManifest {
    AnalyzerAssetManifest {
        name: "ipadic".to_owned(),
        version: "2.7.0".to_owned(),
        sha256: "00".repeat(32),
        size_bytes,
        license: "Apache-2.0".to_owned(),
        source: source.map(str::to_owned),
    }
}

fn manifest(
    analyzer_version: &str,
    normalization: NormalizationPolicy,
    langs: &[(&str, AnalyzerMode, Option<AnalyzerAssetManifest>)],
    channels: &[&str],
    stemmer_langs: &[&str],
) -> AnalyzerManifest {
    // Inserted in the order given: the BTreeMap sorts, and a fixture row lists its
    // languages out of order on purpose.
    let mut map = BTreeMap::new();
    for (lang, mode, dict) in langs {
        map.insert(
            (*lang).to_owned(),
            LangPolicy {
                mode: *mode,
                dict: dict.clone(),
            },
        );
    }
    AnalyzerManifest {
        analyzer_version: analyzer_version.to_owned(),
        normalization,
        langs: map,
        channels: channels.iter().map(|text| (*text).to_owned()).collect(),
        stemmer_langs: stemmer_langs
            .iter()
            .map(|text| (*text).to_owned())
            .collect(),
    }
}

fn fixtures() -> Vec<(&'static str, AnalyzerManifest)> {
    let all_off = NormalizationPolicy {
        nfkc: false,
        casefold: false,
        kana_fold: false,
        khmer_coeng: false,
    };
    vec![
        (
            "portable analyzer",
            MultilingualAnalyzer::portable().manifest(),
        ),
        (
            "empty strings and lists",
            manifest("", all_off.clone(), &[], &[], &[]),
        ),
        (
            "empty language key, empty channel",
            manifest(
                "v4",
                NormalizationPolicy::default(),
                &[("", AnalyzerMode::Portable, None)],
                &[""],
                &[""],
            ),
        ),
        (
            "languages inserted out of order",
            manifest(
                "v4",
                NormalizationPolicy::default(),
                &[
                    ("zh", AnalyzerMode::Morphological, Some(asset(1, None))),
                    ("*", AnalyzerMode::Portable, None),
                    ("ja", AnalyzerMode::Morphological, Some(asset(2, Some("")))),
                    ("ko", AnalyzerMode::Portable, None),
                ],
                &["surface", "stem"],
                &["en", "de"],
            ),
        ),
        (
            "u64::MAX dict size, unicode keys and text",
            manifest(
                "v4-\u{1f1fa}\u{1f1e6}",
                all_off,
                &[
                    (
                        "\u{65e5}\u{672c}",
                        AnalyzerMode::Morphological,
                        Some(asset(u64::MAX, Some("https://example.invalid/\u{e9}"))),
                    ),
                    ("\u{1f600}", AnalyzerMode::Portable, None),
                ],
                &["\u{0}", "\"quoted\"", "back\\slash"],
                &["\u{fffd}"],
            ),
        ),
        (
            "dict with a zero size and no source",
            manifest(
                "v3",
                NormalizationPolicy::default(),
                &[("ja", AnalyzerMode::Morphological, Some(asset(0, None)))],
                &["surface"],
                &[],
            ),
        ),
    ]
}

#[test]
fn the_manifest_hash_keeps_main_bytes() {
    for (name, manifest) in fixtures() {
        let expected = base::canonical_hash(&manifest).expect("base hash");
        assert_eq!(
            canonical_hash(&manifest).expect("hash"),
            expected,
            "free fn, fixture {name}"
        );
        assert_eq!(
            manifest.canonical_hash().expect("hash"),
            expected,
            "method, fixture {name}"
        );
        let expected_hex: String = expected.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            canonical_hash_hex(&manifest).expect("hex"),
            expected_hex,
            "hex, fixture {name}"
        );
        assert_eq!(
            canonical_json(&manifest).expect("json"),
            base::canonical_json(&manifest).expect("base json"),
            "json, fixture {name}"
        );
    }
}

#[test]
fn distinct_fixtures_give_distinct_hashes() {
    let hashes: std::collections::BTreeSet<[u8; 32]> = fixtures()
        .iter()
        .map(|(_, manifest)| canonical_hash(manifest).expect("hash"))
        .collect();
    assert_eq!(hashes.len(), fixtures().len());
}
