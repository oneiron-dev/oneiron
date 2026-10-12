//! Every subprocess the workspace's crates start comes from `oneiron_spawn`.
//! A direct `Command::new` or `Command::from` (std or tokio), a `Command`
//! imported under another name, or a raw `fork`/`posix_spawn` in a crate's
//! non-test source fails here.

use std::path::{Path, PathBuf};

/// What this does not scan, and why.
const OUTSIDE: &[(&str, &str)] = &[
    ("oneiron-spawn", "the helper itself"),
    (
        "oneiron-bench",
        "the benchmark harness, a binary of its own that the server does not link",
    ),
    (
        "oneiron-guest",
        "the microVM guest's init, which runs inside the guest",
    ),
    (
        "oneiron-organ-host/src/bin/oneiron-organ-probe.rs",
        "a standalone probe binary",
    ),
    ("heed", "vendored, not a workspace member"),
    ("paste", "vendored, not a workspace member"),
];

/// Calls that start a process.
const STARTS: &[&str] = &[
    "Command::new(",
    "Command::from(",
    "libc::fork(",
    "libc::vfork(",
    "unistd::fork(",
    "posix_spawn",
];

#[test]
fn every_subprocess_comes_from_the_helper() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crates directory");
    let mut found = Vec::new();
    let mut scanned = 0;
    for entry in std::fs::read_dir(crates).expect("crates") {
        let dir = entry.expect("crate").path();
        let src = dir.join("src");
        if outside(crates, &dir) || !src.is_dir() {
            continue;
        }
        for file in rust_files(&src) {
            let path = file.strip_prefix(crates).unwrap_or(&file);
            if outside(crates, &file) || is_test(path) {
                continue;
            }
            scanned += 1;
            let text = std::fs::read_to_string(&file).expect("source");
            for (index, line) in text.lines().enumerate() {
                if let Some(start) = starts_process(line) {
                    found.push(format!("{}:{}: {start}", path.display(), index + 1));
                }
            }
        }
    }
    assert!(scanned > 100, "only {scanned} source files were scanned");
    assert!(
        found.is_empty(),
        "subprocesses started outside oneiron_spawn:\n{}",
        found.join("\n")
    );
}

/// What in `line` starts a process directly, if anything.
fn starts_process(line: &str) -> Option<&'static str> {
    let code = line.trim_start();
    if code.starts_with("//") {
        return None;
    }
    if let Some(start) = STARTS.iter().copied().find(|start| code.contains(start)) {
        return Some(start);
    }
    code.contains("Command as ")
        .then_some("a Command imported under another name")
}

fn outside(crates: &Path, path: &Path) -> bool {
    let relative = path.strip_prefix(crates).unwrap_or(path);
    OUTSIDE
        .iter()
        .any(|(skipped, _)| relative == Path::new(skipped))
}

/// A test module by the repo's spellings, for a path under the crates
/// directory: a `tests` directory, or a file named `tests.rs`, `*_tests.rs`,
/// `tests_*.rs` or `*_tests_*.rs`.
fn is_test(path: &Path) -> bool {
    path.components().any(|part| part.as_os_str() == "tests")
        || path
            .file_stem()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|stem| stem.split('_').any(|word| word == "tests"))
}

fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).expect("source directory") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            files.extend(rust_files(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
    files
}
