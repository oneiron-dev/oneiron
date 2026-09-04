//! N-API build script.
//!
//! Two jobs: the napi-rs setup this crate has always done, and the ONE-1441
//! SDK-major assertion — the npm package's semver MAJOR must equal the engine's
//! `MEMORY_PACK_VERSION`, because `recall` returns that pack shape and a
//! caller's major version is the only thing telling them which shape they get.
//!
//! The check reads the DECLARATION in the engine source rather than importing
//! the constant. A build script cannot link the crate it is building against,
//! and re-declaring the number here would create exactly the second source of
//! truth the assertion exists to prevent.

extern crate napi_build;

use std::path::{Path, PathBuf};

/// Engine source carrying the `MEMORY_PACK_VERSION` declaration.
const PACK_VERSION_SOURCE: &str = "../oneiron/src/memory/recall.rs";

/// The npm package whose major must match it.
const PACKAGE_JSON: &str = "../../packages/oneiron/package.json";

fn main() {
    napi_build::setup();

    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is always set by cargo"),
    );
    let pack_source = manifest_dir.join(PACK_VERSION_SOURCE);
    let package_json = manifest_dir.join(PACKAGE_JSON);

    println!("cargo:rerun-if-changed={}", pack_source.display());
    println!("cargo:rerun-if-changed={}", package_json.display());

    let pack_version = read_pack_version(&pack_source);
    // The npm package is a sibling artifact, not a build input: a `cargo build`
    // in a source tree that has not assembled it yet must still succeed, so an
    // absent file is skipped rather than failed. The packaging dry-run
    // (`assert-sdk-major.mjs`) is the check that cannot be skipped.
    let Some(npm_major) = read_npm_major(&package_json) else {
        return;
    };
    assert!(
        npm_major == pack_version,
        "npm package major {npm_major} must equal MEMORY_PACK_VERSION {pack_version}; \
         a MemoryPack schema-major change requires an intentional package-major change"
    );
}

/// Extracts `MEMORY_PACK_VERSION: u32 = <n>;` from the engine source.
fn read_pack_version(path: &Path) -> u32 {
    let source = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    for line in source.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("pub const MEMORY_PACK_VERSION: u32 = ") else {
            continue;
        };
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        return digits
            .parse()
            .unwrap_or_else(|error| panic!("MEMORY_PACK_VERSION is not a number: {error}"));
    }
    panic!("no MEMORY_PACK_VERSION declaration in {}", path.display());
}

/// Extracts the semver major from the npm package's `version` field.
///
/// Deliberately a small hand-rolled scan and not a JSON dependency: a build
/// script that pulls a parser into every build to read one field has bought a
/// dependency, a compile, and a supply-chain edge for a substring.
fn read_npm_major(path: &Path) -> Option<u32> {
    let source = std::fs::read_to_string(path).ok()?;
    let index = source.find("\"version\"")?;
    let rest = &source[index + "\"version\"".len()..];
    let open = rest.find('"')?;
    let after_open = &rest[open + 1..];
    let close = after_open.find('"')?;
    let version = &after_open[..close];
    let major = version.split('.').next()?;
    major.parse().ok()
}
