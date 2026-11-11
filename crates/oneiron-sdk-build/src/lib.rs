//! The SDK's generated outputs, produced at build time (untangle slice 4.3, SLICE4-RULED S4-2 G1).
//!
//! The verb table (`scripts/sdk/verbs/`) and the Rust types its rows name are the source; the generated files are
//! not committed. A crate that compiles one calls [`generate`] from its build script with the outputs it includes.
//! The first build script to run for an input digest runs the SDK generator (`oneiron-sdk-generator`, in this
//! process) once, into a directory shared by every crate of the target dir, and each crate copies its own outputs
//! into its `OUT_DIR`, where its `include!` reads them. A crate that ships generated sources in a package of its own
//! (`oneiron-py`'s Python files) places them with [`place`].
//!
//! The digest covers every file the generator may read (the `INPUTS` and every file under the `CRATES` source
//! directories) and the generator's identity: its source ([`GENERATOR_SOURCE_DIGEST`]), the lock file and manifests
//! that decide its build, and the compiler. A change to any of them makes a new run. The run key covers the
//! generator's source, `Cargo.lock`, the manifests and the compiler. It does not see a local override of the
//! generator's dependencies (`[patch]` to a path, `paths` in `.cargo/config`, or `--config`). After changing one,
//! delete `<target dir>/<profile>/sdk-generated`.
//!
//! Cargo reruns a build script only when a file it watches changes, and the watched files are fewer than the files
//! the digest reads: the run's dependency set ([`DEPENDENCIES_FILE`], which the generator writes into the run
//! directory, read again whenever a run is reused). That set is the verb files, `type_names.json`, the hand-written
//! inputs, every crate source file that defined an item the generator resolved (by path or by its crate-wide lookup
//! by name), and every module file it walked. Besides the set, cargo watches the verb directory (a new verb file
//! reruns), `Cargo.lock` and the two manifests, and the dependency file itself, whose time is set far in the past:
//! deleting `sdk-generated` reruns the scripts, and writing the file does not. A body edit in a crate file the
//! generator never resolved from reruns nothing.
//!
//! The limit: a new file, or a new same-named item in a file the generator did not resolve from, is not seen by an
//! incremental build until a watched file changes; delete target/<profile>/sdk-generated to force. An item here is
//! also a serde impl or a macro of a name the generator looked up, and an edit that makes the generator refuse a file
//! it did not resolve from shows the same way. Whenever a script does rerun, the digest sees every change. A clean
//! build always reruns the scripts, and the merge train regenerates the SDK outputs on every train top (TRAIN-REGEN).
//!
//! Each run also leaves the agent-SDK reference (`types.md`, `facade-types.md`, `verbs.md`) in
//! `<target dir>/<profile>/sdk-generated/agent-sdk/`, the local copy of what CI publishes.

use std::collections::BTreeSet;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use std::{env, fs};

use oneiron_sdk_generator::{
    CRATES, DEPENDENCIES_FILE, GENERATOR_SOURCE_DIGEST, INPUTS, write_out_dir,
};

/// Generated files the package builds write beside the generator's inputs (the generator's
/// `PACKAGE_OUTPUTS`). They are outputs, never inputs: the digest and the rerun list leave them out, so a
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

/// How long after the Unix epoch a run's dependency file is dated. Cargo reruns a build script when a watched file
/// is newer than the script's last run or is missing; dated here, the file is never newer, so the run that writes it
/// does not rerun the scripts, and deleting `sdk-generated` (the file with it) does.
const DEPENDENCIES_FILE_AGE: Duration = Duration::from_secs(86_400);

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
    // A reused run states its dependency set as a fresh one does, so cargo watches the same files after either.
    for path in watched(&root, &run, &roots) {
        println!("cargo:rerun-if-changed={}", path.display());
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

/// What the generator may read: its fixed inputs (`INPUTS`, files and the verb directory) and the crate source
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

/// The paths cargo watches for this run, sorted: the run's dependency set (the generator's `DEPENDENCIES_FILE`, paths
/// from `root`) and that file itself (see `DEPENDENCIES_FILE_AGE`), the fixed inputs (`INPUTS`: the hand-written
/// files, `type_names.json` and the verb directory, which cargo scans for any file added, removed or changed under
/// it) and `GENERATOR_BUILD_FILES`. The `CRATES` directories are not watched: cargo scans a watched directory
/// recursively, so any edit under them would rerun this. A run without the file (one this crate's generator did not
/// write) is watched as the digest reads it: every input root that exists. Generated outputs (`PACKAGE_OUTPUTS`) are
/// never watched.
fn watched(root: &Path, run: &Path, roots: &[PathBuf]) -> BTreeSet<PathBuf> {
    let mut paths: BTreeSet<PathBuf> = INPUTS
        .iter()
        .chain(GENERATOR_BUILD_FILES)
        .map(|path| root.join(path))
        .collect();
    let dependencies = run.join(DEPENDENCIES_FILE);
    match fs::read_to_string(&dependencies) {
        Ok(text) => {
            paths.extend(text.lines().map(|path| root.join(path)));
            paths.insert(dependencies);
        }
        // Only paths that exist are named, because a missing path would rerun this on every build.
        Err(_) => paths.extend(roots.iter().filter(|path| path.exists()).cloned()),
    }
    for output in PACKAGE_OUTPUTS {
        paths.remove(&root.join(output));
    }
    paths
}

/// The files that decide how the generator was built, beside its source: the lock file (the resolved versions of its
/// dependencies), the workspace manifest (their declared features, the profiles) and its own manifest. The digest
/// reads them, and they are watched, so a change to one reruns this and the digest names the run at once (a change
/// that alters the generator also rebuilds it, which reruns every build script that calls this crate).
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
    let dependencies = staging.join(DEPENDENCIES_FILE);
    fs::File::options()
        .write(true)
        .open(&dependencies)
        .and_then(|file| file.set_modified(SystemTime::UNIX_EPOCH + DEPENDENCIES_FILE_AGE))
        .unwrap_or_else(|error| panic!("set the time of {} ({error})", dependencies.display()));
    fs::write(staging.join(".complete"), b"").expect("mark the SDK run complete");
    if fs::rename(&staging, run).is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
}
