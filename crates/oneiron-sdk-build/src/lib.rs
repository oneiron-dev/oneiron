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
//! any of them makes a new run. When those cannot name the generator (a path package among its dependencies, or a
//! compiler that does not answer), the calling build script's own executable stands for it, and that crate's run is
//! not shared.
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
/// its build (`GENERATOR_BUILD_FILES`) and the compiler that built it. Those name the generator only when every
/// package it depends on is pinned in `Cargo.lock` (`dependencies_are_pinned`) and the compiler answers; otherwise
/// this build script's own executable, which links the generator, stands for it, and the run is this crate's alone.
fn digest(root: &Path, files: &[PathBuf]) -> u64 {
    let mut hasher = DefaultHasher::new();
    GENERATOR_SOURCE_DIGEST.hash(&mut hasher);
    for file in GENERATOR_BUILD_FILES {
        file.hash(&mut hasher);
        fs::read(root.join(file))
            .unwrap_or_default()
            .hash(&mut hasher);
    }
    let compiler = compiler_version();
    compiler.hash(&mut hasher);
    let lock = fs::read_to_string(root.join("Cargo.lock")).unwrap_or_default();
    if compiler.is_none() || !dependencies_are_pinned(&lock) {
        let executable = env::current_exe()
            .and_then(fs::read)
            .unwrap_or_else(|error| panic!("read this build script's executable ({error})"));
        executable.hash(&mut hasher);
    }
    for file in files {
        file.strip_prefix(root).unwrap_or(file).hash(&mut hasher);
        fs::read(file).unwrap_or_default().hash(&mut hasher);
    }
    hasher.finish()
}

/// `$RUSTC -vV`: the release, commit and host of the compiler cargo builds with (and so built the generator), or
/// `None` when it cannot be asked. A new compiler rebuilds every build script, so this is asked again then.
#[allow(
    clippy::disallowed_methods,
    reason = "a build script asks the compiler cargo names for its version; oneiron_spawn is the engine's spawn path"
)]
fn compiler_version() -> Option<Vec<u8>> {
    let rustc = env::var_os("RUSTC")?;
    std::process::Command::new(rustc)
        .arg("-vV")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| output.stdout)
}

/// Whether every package in the generator's dependency closure in `lock` (a `Cargo.lock`) comes from a registry or a
/// git commit, whose bytes the lock file names by version and source. A path package (a workspace crate, or a
/// `[patch]` to a local copy) has no `source` line: its files can change while the lock file stays the same. A
/// closure that cannot be read (no generator entry, a dependency with no entry) counts as not pinned.
fn dependencies_are_pinned(lock: &str) -> bool {
    let packages = lock_packages(lock);
    let Some(generator) = packages
        .iter()
        .position(|package| package.name == "oneiron-sdk-generator")
    else {
        return false;
    };
    let mut seen = vec![false; packages.len()];
    let mut pending = vec![generator];
    while let Some(index) = pending.pop() {
        if std::mem::replace(&mut seen[index], true) {
            continue;
        }
        let package = &packages[index];
        if index != generator && package.source.is_none() {
            return false;
        }
        for dependency in &package.dependencies {
            // `name`, `name version` or `name version (source)`, as Cargo writes them.
            let mut parts = dependency.splitn(3, ' ');
            let name = parts.next().unwrap_or_default();
            let version = parts.next();
            let source = parts
                .next()
                .map(|source| source.trim_start_matches('(').trim_end_matches(')'));
            let before = pending.len();
            pending.extend(
                packages
                    .iter()
                    .enumerate()
                    .filter(|(_, candidate)| {
                        candidate.name == name
                            && version.is_none_or(|version| candidate.version == version)
                            && source.is_none_or(|source| candidate.source == Some(source))
                    })
                    .map(|(candidate, _)| candidate),
            );
            if pending.len() == before {
                return false;
            }
        }
    }
    true
}

/// One `[[package]]` entry of a `Cargo.lock`.
#[derive(Default)]
struct LockPackage<'a> {
    name: &'a str,
    version: &'a str,
    source: Option<&'a str>,
    dependencies: Vec<&'a str>,
}

/// The `[[package]]` entries of a `Cargo.lock`, as Cargo writes it: one `key = "value"` per line, and the
/// `dependencies = [` list one quoted entry per line up to `]`. Other tables end an entry.
fn lock_packages(lock: &str) -> Vec<LockPackage<'_>> {
    let mut packages: Vec<LockPackage<'_>> = Vec::new();
    let (mut in_package, mut in_dependencies) = (false, false);
    for line in lock.lines() {
        if line == "[[package]]" {
            packages.push(LockPackage::default());
            (in_package, in_dependencies) = (true, false);
            continue;
        }
        if line.starts_with('[') {
            (in_package, in_dependencies) = (false, false);
            continue;
        }
        let Some(package) = packages.last_mut().filter(|_| in_package) else {
            continue;
        };
        if in_dependencies {
            if line.trim() == "]" {
                in_dependencies = false;
            } else {
                package
                    .dependencies
                    .push(line.trim().trim_end_matches(',').trim_matches('"'));
            }
        } else if let Some(items) = line.strip_prefix("dependencies = [") {
            match items.strip_suffix(']') {
                // A list on one line.
                Some(items) => package.dependencies.extend(
                    items
                        .split(',')
                        .map(|item| item.trim().trim_matches('"'))
                        .filter(|item| !item.is_empty()),
                ),
                None => in_dependencies = true,
            }
        } else if let Some(value) = lock_value(line, "name") {
            package.name = value;
        } else if let Some(value) = lock_value(line, "version") {
            package.version = value;
        } else if let Some(value) = lock_value(line, "source") {
            package.source = Some(value);
        }
    }
    packages
}

/// The value of a `key = "value"` line.
fn lock_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.strip_prefix(key)?
        .strip_prefix(" = \"")?
        .strip_suffix('"')
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

#[cfg(test)]
mod tests {
    use super::dependencies_are_pinned;

    const REGISTRY: &str = "registry+https://github.com/rust-lang/crates.io-index";

    /// A lock file with the generator depending on `regex`, and `regex` on the given entry, followed by `extra`.
    fn lock(regex_dependency: &str, extra: &str) -> String {
        format!(
            "version = 4\n\n[[package]]\nname = \"oneiron-sdk-generator\"\nversion = \"0.1.0\"\ndependencies = [\n \
             \"regex\",\n]\n\n[[package]]\nname = \"regex\"\nversion = \"1.13.1\"\nsource = \"{REGISTRY}\"\n\
             checksum = \"00\"\ndependencies = [\n \"{regex_dependency}\",\n]\n{extra}"
        )
    }

    #[test]
    fn the_workspace_lock_pins_the_generator() {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock"))
                .expect("the workspace's Cargo.lock");
        assert!(dependencies_are_pinned(&text));
    }

    #[test]
    fn registry_and_git_packages_are_pinned() {
        let text = lock(
            "memchr",
            "\n[[package]]\nname = \"memchr\"\nversion = \"2.8.3\"\nsource = \"git+https://example.com/memchr#abc\"\n",
        );
        assert!(dependencies_are_pinned(&text));
    }

    #[test]
    fn a_path_package_in_the_closure_is_not_pinned() {
        let text = lock(
            "memchr",
            "\n[[package]]\nname = \"memchr\"\nversion = \"2.8.3\"\n",
        );
        assert!(!dependencies_are_pinned(&text));
    }

    #[test]
    fn a_path_package_outside_the_closure_does_not_count() {
        let text = lock(
            "memchr",
            &format!(
                "\n[[package]]\nname = \"memchr\"\nversion = \"2.8.3\"\nsource = \"{REGISTRY}\"\n\n[[package]]\n\
                 name = \"oneiron\"\nversion = \"0.1.0\"\ndependencies = [\n \"memchr\",\n]\n"
            ),
        );
        assert!(dependencies_are_pinned(&text));
    }

    #[test]
    fn a_versioned_entry_picks_its_version() {
        let two = |path_version: &str| {
            format!(
                "\n[[package]]\nname = \"memchr\"\nversion = \"2.8.3\"\nsource = \"{REGISTRY}\"\n\n[[package]]\n\
                 name = \"memchr\"\nversion = \"{path_version}\"\n"
            )
        };
        assert!(dependencies_are_pinned(&lock(
            "memchr 2.8.3",
            &two("1.0.0")
        )));
        assert!(!dependencies_are_pinned(&lock(
            "memchr 1.0.0",
            &two("1.0.0")
        )));
        assert!(dependencies_are_pinned(&lock(
            &format!("memchr 2.8.3 ({REGISTRY})"),
            &two("1.0.0")
        )));
    }

    #[test]
    fn a_one_line_dependency_list_is_read() {
        let text = "[[package]]\nname = \"oneiron-sdk-generator\"\nversion = \"0.1.0\"\ndependencies = [\"memchr\"]\n\n\
                    [[package]]\nname = \"memchr\"\nversion = \"2.8.3\"\n";
        assert!(!dependencies_are_pinned(text));
    }

    #[test]
    fn an_unreadable_closure_is_not_pinned() {
        assert!(!dependencies_are_pinned(""));
        assert!(!dependencies_are_pinned(&lock("memchr", "")));
    }
}
