//! License + asset governance gate for the analyzer (plan ONE-317 §11).
//!
//! Runs in the standard `cargo test` suite — no network access, no data
//! files. Covers:
//!
//! 1. `jieba-rs` must be declared with `default-features = false` so the
//!    upstream `default-dict` (unclear provenance, not redistributable)
//!    is never compiled in.
//! 2. `lindera` must be declared with `default-features = false` so no
//!    `embed-*-dic` feature is active — dicts load from `dict_search_paths`
//!    at runtime only.
//! 3. Any `AnalyzerAssetManifest` emitted by the default analyzer carries
//!    an allowed license (per the Apache-2.0 / MIT / BSD / Unicode-3.0 /
//!    ISC / BSL-1.0 / MPL-2.0 / Zlib allowlist in deny.toml), a non-zero
//!    sha256, and a `source` URL.

use std::collections::BTreeSet;
use std::io::Write;

use oneiron::analyzer::{AnalyzerAssetManifest, MultilingualAnalyzer};

const ONEIRON_CARGO_TOML: &str = include_str!("../Cargo.toml");

fn allowed_licenses() -> BTreeSet<&'static str> {
    // Must stay in sync with deny.toml [licenses].allow.
    [
        "Apache-2.0",
        "Apache-2.0 WITH LLVM-exception",
        "MIT",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "BSL-1.0",
        "ISC",
        "MPL-2.0",
        "Unicode-3.0",
        "Zlib",
    ]
    .into_iter()
    .collect()
}

fn find_line_starting_with(haystack: &str, needle: &str) -> Option<String> {
    haystack
        .lines()
        .find(|line| line.trim_start().starts_with(needle))
        .map(std::borrow::ToOwned::to_owned)
}

#[test]
fn jieba_rs_default_dict_disabled() {
    let line = find_line_starting_with(ONEIRON_CARGO_TOML, "jieba-rs")
        .expect("jieba-rs dependency line missing from crates/oneiron/Cargo.toml");
    assert!(
        line.contains("default-features = false"),
        "jieba-rs must be declared with `default-features = false` to keep the \
         upstream default-dict out of the binary; current line: {line}"
    );
}

#[test]
fn lindera_embed_dic_disabled() {
    let line = find_line_starting_with(ONEIRON_CARGO_TOML, "lindera")
        .expect("lindera dependency line missing from crates/oneiron/Cargo.toml");
    assert!(
        line.contains("default-features = false"),
        "lindera must be declared with `default-features = false` so no \
         `embed-*-dic` feature is active; current line: {line}"
    );
    assert!(
        !line.contains("embed-"),
        "lindera must not enable any `embed-*-dic` feature; dicts load from \
         dict_search_paths at runtime only; current line: {line}"
    );
}

#[test]
fn default_analyzer_emits_no_disallowed_assets() {
    let analyzer =
        MultilingualAnalyzer::discover(&[]).expect("discover with empty search paths must succeed");
    let manifest = analyzer.manifest();
    let allowed = allowed_licenses();

    for (lang, policy) in &manifest.langs {
        let Some(asset) = policy.dict.as_ref() else {
            continue;
        };
        // ZH dicts are user-supplied per plan §2.3 — the packager is
        // responsible for provenance; the "user-supplied" sentinel
        // license is accepted only for `zh`.
        if lang == "zh" && asset.license == "user-supplied" {
            continue;
        }
        assert_asset_policy(lang, asset, &allowed);
    }
}

/// Exercises [`AnalyzerAssetManifest::probe_file`] end-to-end against a
/// real file. CI never has dicts on disk, so the loop above is vacuous;
/// this test ensures the fingerprint code itself is covered (plan §11).
#[test]
fn probe_file_fingerprints_temp_file_correctly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("fake.dic");
    let mut f = std::fs::File::create(&path).expect("create");
    f.write_all(b"hello world").expect("write");
    drop(f);

    let asset = AnalyzerAssetManifest::probe_file(
        "test-dict",
        "v0",
        "Apache-2.0",
        Some("https://example.invalid/src".to_string()),
        &path,
    )
    .expect("probe must succeed on readable file");

    assert_eq!(asset.name, "test-dict");
    assert_eq!(asset.version, "v0");
    assert_eq!(asset.license, "Apache-2.0");
    assert_eq!(asset.size_bytes, 11);
    // sha256("hello world") = b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
    assert_eq!(
        asset.sha256,
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );
    assert_asset_policy("test", &asset, &allowed_licenses());
}

fn assert_asset_policy(lang: &str, asset: &AnalyzerAssetManifest, allowed: &BTreeSet<&str>) {
    assert!(
        allowed.contains(asset.license.as_str()),
        "analyzer asset for lang `{lang}` has disallowed license `{}`; \
         allowed set: {allowed:?}",
        asset.license
    );
    assert!(
        asset.sha256.len() == 64
            && asset
                .sha256
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "analyzer asset for lang `{lang}` has malformed sha256 `{}` \
         (expected 64 lowercase hex chars)",
        asset.sha256
    );
    assert!(
        asset.sha256.chars().any(|c| c != '0'),
        "analyzer asset for lang `{lang}` has all-zero sha256 — fingerprint \
         was not populated",
    );
    assert!(
        asset
            .source
            .as_ref()
            .is_some_and(|s| s.starts_with("http://") || s.starts_with("https://")),
        "analyzer asset for lang `{lang}` missing upstream source URL",
    );
    assert!(
        asset.size_bytes > 0,
        "analyzer asset for lang `{lang}` has zero size_bytes — dict probe did \
         not populate file size",
    );
}
