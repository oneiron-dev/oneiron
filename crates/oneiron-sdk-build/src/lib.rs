//! The SDK's generated outputs, produced at build time (untangle slice 4.3, SLICE4-RULED S4-2 G1).
//!
//! The verb table (`scripts/sdk/verbs/`) and the Rust types its rows name are the source; the generated files are
//! not committed. A crate that compiles one calls [`generate`] from its build script with the outputs it includes.
//! The first build script to run for an input digest runs `scripts/sdk/generate.py` once, into a directory shared
//! by every crate of the target dir, and each crate copies its own outputs into its `OUT_DIR`, where its `include!`
//! reads them. A crate that ships generated sources in a package of its own (`oneiron-py`'s Python files) places
//! them with [`place`].
//!
//! Each run also leaves the agent-SDK reference (`types.md`, `facade-types.md`, `verbs.md`) in
//! `<target dir>/<profile>/sdk-generated/agent-sdk/`, the local copy of what CI publishes.
//!
//! Python 3 is a build requirement until the generator is ported to Rust (FIX-LIST SDK-GENERATOR-RUST, the first
//! row after the untangle). A build that cannot run it fails with the README section to read.

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
/// files whose names it reads.
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

/// Generated files the package builds write into the input directories above (`PACKAGE_OUTPUTS` in
/// `scripts/sdk/generate.py`). They are outputs, never inputs: the digest and the rerun list leave them out, so a
/// package build that writes them does not make the next cargo build run the generator again.
const PACKAGE_OUTPUTS: &[&str] = &[
    "packages/oneiron/src/facade-types.ts",
    "packages/oneiron/src/agent-verbs.ts",
    "packages/oneiron/src/facade-verbs.ts",
    "packages/oneiron/src/native-verbs.ts",
    "crates/oneiron-py/python/oneiron/_facade_verbs.py",
    "crates/oneiron-py/python/oneiron/_facade_verbs.pyi",
    "crates/oneiron-py/python/oneiron/facade_types.pyi",
];

/// The agent-SDK reference files each run writes under `docs/agent-sdk/`.
const DOCS: &[&str] = &["types.md", "facade-types.md", "verbs.md"];

/// Copies `outputs` (paths from the workspace root, as the generator names them) into this crate's `OUT_DIR`,
/// each under its file name, running the generator first when no run for these inputs exists yet.
///
/// # Panics
///
/// When the workspace, `OUT_DIR` or an output cannot be found, or the generator cannot run or fails: a build
/// script reports by panicking.
pub fn generate(outputs: &[&str]) {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("cargo sets OUT_DIR"));
    let placed: Vec<(&str, PathBuf)> = outputs
        .iter()
        .map(|output| {
            let name = Path::new(output)
                .file_name()
                .expect("an output names a file");
            (*output, out_dir.join(name))
        })
        .collect();
    place(&placed);
}

/// Writes each output (a path from the workspace root, as the generator names it) to the path paired with it,
/// running the generator first when no run for these inputs exists yet. An unchanged output keeps its time, so
/// nothing that reads it rebuilds.
///
/// # Panics
///
/// As [`generate`].
pub fn place(outputs: &[(&str, PathBuf)]) {
    let manifest =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"));
    let root = manifest
        .ancestors()
        .find(|dir| dir.join("scripts/sdk/generate.py").is_file())
        .unwrap_or_else(|| panic!("no scripts/sdk/generate.py above {}", manifest.display()))
        .to_path_buf();
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("cargo sets OUT_DIR"));
    let files = input_files(&root);
    for file in &files {
        println!("cargo:rerun-if-changed={}", file.display());
    }
    // A new verb is a new file: the directory itself is watched too.
    println!(
        "cargo:rerun-if-changed={}",
        root.join("scripts/sdk/verbs").display()
    );
    println!("cargo:rerun-if-env-changed=ONEIRON_PYTHON");
    let digest = digest(&root, &files);
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
    for (output, to) in outputs {
        let text = fs::read(run.join(output)).unwrap_or_else(|error| {
            panic!("the SDK generator wrote no {output} ({error}); see {README_SECTION}")
        });
        write_if_changed(to, &text);
    }
    for name in DOCS {
        if let Ok(text) = fs::read(run.join("docs/agent-sdk").join(name)) {
            write_if_changed(&shared.join("agent-sdk").join(name), &text);
        }
    }
}

fn write_if_changed(to: &Path, text: &[u8]) {
    if fs::read(to).ok().as_deref() == Some(text) {
        return;
    }
    if let Some(dir) = to.parent() {
        fs::create_dir_all(dir)
            .unwrap_or_else(|error| panic!("create {} ({error})", dir.display()));
    }
    fs::write(to, text).unwrap_or_else(|error| panic!("write {} ({error})", to.display()));
}

/// Every input file: under the fixed inputs and each crate source directory `facade_types.py` lists, generated
/// outputs excluded.
fn input_files(root: &Path) -> Vec<PathBuf> {
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
    let generated: Vec<PathBuf> = PACKAGE_OUTPUTS.iter().map(|path| root.join(path)).collect();
    let mut files = Vec::new();
    for path in &paths {
        collect(path, &generated, &mut files);
    }
    files.sort();
    files.dedup();
    files
}

/// A digest of every input file's path and bytes.
fn digest(root: &Path, files: &[PathBuf]) -> u64 {
    let mut hasher = DefaultHasher::new();
    for file in files {
        file.strip_prefix(root).unwrap_or(file).hash(&mut hasher);
        fs::read(file).unwrap_or_default().hash(&mut hasher);
    }
    hasher.finish()
}

fn collect(path: &Path, generated: &[PathBuf], files: &mut Vec<PathBuf>) {
    if generated.iter().any(|output| output == path) {
        return;
    }
    if path.is_file() {
        files.push(path.to_path_buf());
        return;
    }
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name == "generated"
            || name == "target"
            || name == "node_modules"
            || name == "__pycache__"
        {
            continue;
        }
        collect(&entry.path(), generated, files);
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
