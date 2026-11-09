//! The SDK's generated Rust outputs, produced at build time (untangle slice 4.3, SLICE4-RULED S4-2 G1).
//!
//! The verb table (`scripts/sdk/verbs/`) and the Rust types its rows name are the source; the generated files are
//! not committed. A crate that compiles one calls [`generate`] from its build script with the outputs it includes.
//! The first build script to run for an input digest runs `scripts/sdk/generate.py` once, into a directory shared
//! by every crate of the target dir, and each crate copies its own outputs into its `OUT_DIR`, where its `include!`
//! reads them.
//!
//! Python 3 is a build requirement until the generator is ported to Rust (FIX-LIST SDK-GENERATOR-RUST, before the
//! first crates.io publish or `v*` tag). A build that cannot run it fails with the README section to read.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs};

/// Where a build that cannot run the generator is pointed.
pub const README_SECTION: &str =
    "README.md, section \"Building from source\" (Python 3 runs the SDK generator)";

/// The inputs the generator reads beside the Rust crates its type inventory parses (`CRATES` in
/// `scripts/sdk/facade_types.py`, read from that file): the verb table and the generator, and the hand-written
/// files whose names or marked blocks it reads.
const INPUTS: &[&str] = &[
    "scripts/sdk",
    "packages/oneiron/src",
    "packages/oneiron/scripts",
    "packages/oneiron/README.md",
    "crates/oneiron-py/python/oneiron",
    "crates/oneiron-py/src",
    "crates/oneiron-uniffi/src",
    "crates/oneiron-server/src/api/mcp_gateway/tasks_response.rs",
];

/// Copies `outputs` (paths from the workspace root, as the generator names them) into this crate's `OUT_DIR`,
/// each under its file name, running the generator first when no run for these inputs exists yet.
///
/// # Panics
///
/// When the workspace, `OUT_DIR` or an output cannot be found, or the generator cannot run or fails: a build
/// script reports by panicking.
pub fn generate(outputs: &[&str]) {
    let manifest =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"));
    let root = manifest
        .ancestors()
        .find(|dir| dir.join("scripts/sdk/generate.py").is_file())
        .unwrap_or_else(|| panic!("no scripts/sdk/generate.py above {}", manifest.display()))
        .to_path_buf();
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("cargo sets OUT_DIR"));
    let inputs = inputs(&root);
    for input in &inputs {
        println!("cargo:rerun-if-changed={}", input.display());
    }
    println!("cargo:rerun-if-env-changed=ONEIRON_PYTHON");
    let digest = digest(&root, &inputs);
    // OUT_DIR is <target dir>/[<triple>/]<profile>/build/<package>/out: the run is shared at the profile.
    let shared = out_dir
        .ancestors()
        .nth(3)
        .expect("OUT_DIR sits under the profile directory")
        .join("sdk-generated");
    let run = shared.join(format!("{digest:016x}"));
    if !run.join(".complete").is_file() {
        run_generator(&root, &shared, &run);
    }
    for output in outputs {
        let from = run.join(output);
        let text = fs::read(&from).unwrap_or_else(|error| {
            panic!("the SDK generator wrote no {output} ({error}); see {README_SECTION}")
        });
        let name = Path::new(output)
            .file_name()
            .expect("an output names a file");
        let to = out_dir.join(name);
        // An unchanged output keeps its time, so nothing that includes it rebuilds.
        if fs::read(&to).ok().as_deref() != Some(text.as_slice()) {
            fs::write(&to, text).expect("write the output into OUT_DIR");
        }
    }
}

/// Every input path: the fixed ones and each crate source directory `facade_types.py` lists.
fn inputs(root: &Path) -> Vec<PathBuf> {
    let facade_types = fs::read_to_string(root.join("scripts/sdk/facade_types.py"))
        .expect("read scripts/sdk/facade_types.py");
    let mut paths: Vec<PathBuf> = INPUTS.iter().map(|input| root.join(input)).collect();
    let crates = facade_types
        .split_once("CRATES = {")
        .and_then(|(_, rest)| rest.split_once('}'))
        .expect("facade_types.py declares CRATES")
        .0;
    for line in crates.lines() {
        if let Some((_, rest)) = line.split_once(": '")
            && let Some((dir, _)) = rest.split_once('\'')
        {
            paths.push(root.join(dir));
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

/// A digest of every input file's path and bytes, generated outputs excluded.
fn digest(root: &Path, inputs: &[PathBuf]) -> u64 {
    let mut files = Vec::new();
    for input in inputs {
        collect(input, &mut files);
    }
    files.sort();
    let mut hasher = DefaultHasher::new();
    for file in files {
        file.strip_prefix(root).unwrap_or(&file).hash(&mut hasher);
        fs::read(&file).unwrap_or_default().hash(&mut hasher);
    }
    hasher.finish()
}

fn collect(path: &Path, files: &mut Vec<PathBuf>) {
    if path.is_file() {
        files.push(path.to_path_buf());
        return;
    }
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let child = entry.path();
        let name = entry.file_name();
        if name == "generated"
            || name == "target"
            || name == "node_modules"
            || name == "__pycache__"
        {
            continue;
        }
        collect(&child, files);
    }
}

/// Runs the generator into a private directory and publishes it as `run`. Two builds that race publish the same
/// bytes; the loser's directory is dropped.
fn run_generator(root: &Path, shared: &Path, run: &Path) {
    fs::create_dir_all(shared).expect("create the shared SDK output directory");
    let staging = shared.join(format!(
        "{}.staging-{}",
        run.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("run"),
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&staging);
    let python = env::var("ONEIRON_PYTHON")
        .unwrap_or_else(|_| if cfg!(windows) { "python" } else { "python3" }.to_owned());
    let status = Command::new(&python)
        .arg(root.join("scripts/sdk/generate.py"))
        .arg("--out-dir")
        .arg(&staging)
        .current_dir(root)
        .status()
        .unwrap_or_else(|error| {
            panic!("could not run `{python}` for the SDK generator ({error}); see {README_SECTION}")
        });
    assert!(
        status.success(),
        "the SDK generator failed ({status}); run `{python} scripts/sdk/generate.py --out-dir <dir>` to see why; \
         see {README_SECTION}"
    );
    fs::write(staging.join(".complete"), b"").expect("mark the SDK run complete");
    if fs::rename(&staging, run).is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
}
