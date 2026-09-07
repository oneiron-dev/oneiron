//! Asserts the PyPI major still equals the engine's `MEMORY_PACK_VERSION`.
//!
//! Same contract as `oneiron-napi/build.rs`, from the other side: `recall`
//! returns the engine `MemoryPack`, and this distribution's semver MAJOR is
//! the only thing telling an installer which pack shape they get.
//!
//! The engine number is read from its DECLARATION rather than imported,
//! because a build script cannot link the crate it is building against and
//! re-declaring the constant would create the second source of truth this
//! check exists to prevent.

use std::path::{Path, PathBuf};

/// Engine source carrying the `MEMORY_PACK_VERSION` declaration.
const PACK_VERSION_SOURCE: &str = "../oneiron/src/memory/recall.rs";

fn main() {
    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is always set by cargo"),
    );
    let pack_source = manifest_dir.join(PACK_VERSION_SOURCE);

    println!("cargo:rerun-if-changed={}", pack_source.display());
    println!("cargo:rerun-if-changed=Cargo.toml");

    let pack_version = read_pack_version(&pack_source);
    let crate_major: u32 = std::env::var("CARGO_PKG_VERSION_MAJOR")
        .expect("CARGO_PKG_VERSION_MAJOR is always set by cargo")
        .parse()
        .expect("cargo always sets a numeric major");

    assert!(
        crate_major == pack_version,
        "oneiron-py major {crate_major} must equal MEMORY_PACK_VERSION {pack_version}; \
         a MemoryPack schema-major change requires an intentional package-major change"
    );
}

/// Extracts `MEMORY_PACK_VERSION: u32 = <n>;` from the engine source.
fn read_pack_version(path: &Path) -> u32 {
    let source = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    for line in source.lines() {
        let Some(rest) = line
            .trim()
            .strip_prefix("pub const MEMORY_PACK_VERSION: u32 = ")
        else {
            continue;
        };
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        return digits
            .parse()
            .unwrap_or_else(|error| panic!("MEMORY_PACK_VERSION is not a number: {error}"));
    }
    panic!("no MEMORY_PACK_VERSION declaration in {}", path.display());
}
