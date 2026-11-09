//! Sets `GENERATOR_SOURCE_DIGEST` (exposed as `oneiron_sdk_generator::GENERATOR_SOURCE_DIGEST`): a digest of every
//! file under this crate's `src/`, each file's path from `src/` and its bytes, in path order. `oneiron-sdk-build`
//! mixes it into the digest that names a build's shared run directory, so a change to the generator's code makes a
//! new run instead of reusing one the old code wrote. The Python generator had this for free: its `scripts/sdk/*.py`
//! files were digest inputs.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::{env, fs};

fn main() {
    println!("cargo:rerun-if-changed=src");
    let manifest =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"));
    let src = manifest.join("src");
    let mut files = Vec::new();
    collect(&src, &mut files);
    // Path order compares components, so the order does not depend on the separator.
    files.sort();
    let mut hasher = DefaultHasher::new();
    for file in &files {
        file.strip_prefix(&src)
            .expect("a source file lies under src")
            .hash(&mut hasher);
        fs::read(file)
            .unwrap_or_else(|error| panic!("read {} ({error})", file.display()))
            .hash(&mut hasher);
    }
    println!(
        "cargo:rustc-env=GENERATOR_SOURCE_DIGEST={:016x}",
        hasher.finish()
    );
}

/// Every file under `dir`, at any depth.
fn collect(dir: &Path, files: &mut Vec<PathBuf>) {
    let entries =
        fs::read_dir(dir).unwrap_or_else(|error| panic!("read {} ({error})", dir.display()));
    for entry in entries {
        let entry = entry.unwrap_or_else(|error| panic!("read {} ({error})", dir.display()));
        let path = entry.path();
        if entry
            .file_type()
            .unwrap_or_else(|error| panic!("read {} ({error})", path.display()))
            .is_dir()
        {
            collect(&path, files);
        } else {
            files.push(path);
        }
    }
}
