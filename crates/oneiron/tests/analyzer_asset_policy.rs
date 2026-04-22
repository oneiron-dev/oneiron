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
//!    ISC / BSL-1.0 / MPL-2.0 allowlist in deny.toml), a non-zero sha256,
//!    and a `source` URL.

use std::collections::BTreeSet;

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
    ]
    .into_iter()
    .collect()
}

fn find_line_starting_with(haystack: &str, needle: &str) -> Option<String> {
    haystack
        .lines()
        .find(|line| line.trim_start().starts_with(needle))
        .map(|s| s.to_owned())
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
        assert_asset_policy(lang, asset, &allowed);
    }
}

fn assert_asset_policy(lang: &str, asset: &AnalyzerAssetManifest, allowed: &BTreeSet<&str>) {
    assert!(
        allowed.contains(asset.license.as_str()),
        "analyzer asset for lang `{lang}` has disallowed license `{}`; \
         allowed set: {allowed:?}",
        asset.license
    );
    assert!(
        asset.sha256.len() == 64 && asset.sha256.chars().all(|c| c.is_ascii_hexdigit()),
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
