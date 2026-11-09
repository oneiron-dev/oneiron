//! The SDK's generated outputs, produced at build time (untangle slice 4.3, SLICE4-RULED S4-2 G1).
//!
//! The verb table (`scripts/sdk/verbs/`) and the Rust types its rows name are the source; the generated files are
//! not committed. A crate that compiles one calls [`generate`] from its build script with the outputs it includes.
//! The first build script to run for an input digest runs the SDK generator (`oneiron-sdk-generator`, in this
//! process) once, into a directory shared by every crate of the target dir, and each crate copies its own outputs
//! into its `OUT_DIR`, where its `include!` reads them. A crate that ships generated sources in a package of its own
//! (`oneiron-py`'s Python files) places them with [`place`].
//!
//! The digest covers every file the generator reads and the generator's identity: its source
//! ([`GENERATOR_SOURCE_DIGEST`]), the lock file and manifests that decide its build, and the compiler. A change to
//! any of them makes a new run. One change is not seen: a local override of one of the generator's dependencies (a
//! `[patch]` to a path, `paths` in a cargo configuration, `--config`) whose files change while the lock file and the
//! manifests stay the same. After changing such an override, delete `<target dir>/<profile>/sdk-generated`.
//!
//! Each run also leaves the agent-SDK reference (`types.md`, `facade-types.md`, `verbs.md`) in
//! `<target dir>/<profile>/sdk-generated/agent-sdk/`, the local copy of what CI publishes.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::{env, fs};

use oneiron_sdk_generator::{CRATES, GENERATOR_SOURCE_DIGEST, INPUTS, write_out_dir};

/// Generated files the package builds write beside the generator's inputs (`PACKAGE_OUTPUTS` in
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
/// When the workspace, `OUT_DIR` or an output cannot be found, or the generator fails (with the generator's
/// message): a build script reports by panicking.
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
    // The generator binary's rule for the repository root, from this crate's directory.
    let root = manifest
        .ancestors()
        .find(|dir| dir.join("scripts/sdk/verbs").is_dir())
        .unwrap_or_else(|| panic!("no scripts/sdk/verbs above {}", manifest.display()))
        .to_path_buf();
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("cargo sets OUT_DIR"));
    let roots = input_roots(&root);
    let files = input_files(&root, &roots);
    for file in &files {
        println!("cargo:rerun-if-changed={}", file.display());
    }
    // A new file (a verb, or a Rust file the type inventory reads) is in no list above, so every input directory is
    // watched too: cargo scans a watched directory for any file added, removed or changed under it. Only directories
    // that exist are named, because a missing path would rerun this on every build.
    for dir in roots.iter().filter(|path| path.is_dir()) {
        println!("cargo:rerun-if-changed={}", dir.display());
    }
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
        let text = fs::read(run.join(output))
            .unwrap_or_else(|error| panic!("the SDK generator wrote no {output} ({error})"));
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

/// What the generator reads: its fixed inputs (`INPUTS`, files and the verb directory) and the crate source
/// directories its type inventory reads (`CRATES`).
fn input_roots(root: &Path) -> Vec<PathBuf> {
    INPUTS
        .iter()
        .copied()
        .chain(CRATES.iter().map(|(_, dir)| *dir))
        .map(|path| root.join(path))
        .collect()
}

/// Every input file under `roots`, generated outputs excluded.
fn input_files(root: &Path, roots: &[PathBuf]) -> Vec<PathBuf> {
    let generated: Vec<PathBuf> = PACKAGE_OUTPUTS.iter().map(|path| root.join(path)).collect();
    let mut files = Vec::new();
    for path in roots {
        collect(path, &generated, &mut files);
    }
    files.sort();
    files.dedup();
    files
}

/// The files that decide how the generator was built, beside its source: the lock file (the resolved versions of its
/// dependencies), the workspace manifest (their declared features, the profiles) and its own manifest. They are read
/// here, not watched: a change to them that changes the generator rebuilds it, which rebuilds and reruns every build
/// script that calls this crate, and the digest then names a new run. A change that rebuilds nothing changes no
/// generator.
const GENERATOR_BUILD_FILES: &[&str] = &[
    "Cargo.lock",
    "Cargo.toml",
    "crates/oneiron-sdk-generator/Cargo.toml",
];

/// A digest of the generator's identity and every input file's path and bytes, so a run directory an older generator
/// wrote is not reused. The identity is the generator's own source (`GENERATOR_SOURCE_DIGEST`), the files that decide
/// its build (`GENERATOR_BUILD_FILES`) and the compiler that built it (the local overrides the module doc names
/// excepted).
fn digest(root: &Path, files: &[PathBuf]) -> u64 {
    let mut hasher = DefaultHasher::new();
    GENERATOR_SOURCE_DIGEST.hash(&mut hasher);
    for file in GENERATOR_BUILD_FILES {
        file.hash(&mut hasher);
        fs::read(root.join(file))
            .unwrap_or_default()
            .hash(&mut hasher);
    }
    compiler_version().hash(&mut hasher);
    for file in files {
        file.strip_prefix(root).unwrap_or(file).hash(&mut hasher);
        fs::read(file).unwrap_or_default().hash(&mut hasher);
    }
    hasher.finish()
}

/// `$RUSTC -vV`: the release, commit and host of the compiler cargo builds with (and so built the generator). A new
/// compiler rebuilds every build script, so this is asked again then.
///
/// # Panics
///
/// When the compiler cannot be asked: an unknown compiler cannot name a run, and an empty answer would match the
/// run another compiler's generator wrote.
#[allow(
    clippy::disallowed_methods,
    reason = "a build script asks the compiler cargo names for its version; oneiron_spawn is the engine's spawn path"
)]
fn compiler_version() -> Vec<u8> {
    let rustc = env::var_os("RUSTC").expect("cargo sets RUSTC");
    let output = std::process::Command::new(&rustc)
        .arg("-vV")
        .output()
        .unwrap_or_else(|error| panic!("run `{} -vV` ({error})", rustc.display()));
    assert!(
        output.status.success(),
        "`{} -vV` failed ({})",
        rustc.display(),
        output.status
    );
    output.stdout
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
/// bytes; the loser's directory is dropped. The generator runs in this process (`write_out_dir`, on a thread of its
/// own with a 256 MiB stack); a failure panics with its message.
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
    write_out_dir(root, &staging).unwrap_or_else(|error| panic!("{error}"));
    fs::write(staging.join(".complete"), b"").expect("mark the SDK run complete");
    if fs::rename(&staging, run).is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
}
