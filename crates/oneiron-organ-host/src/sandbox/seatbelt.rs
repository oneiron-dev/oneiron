//! The filesystem fence on macOS (FIX 7885, ARCH-0075): a third-party organ
//! starts through Seatbelt's `sandbox-exec`, under a profile that denies
//! every file operation but these. It reads the system's own files, its
//! program and its read dirs; it reads and writes its write dirs,
//! `/private/tmp` and `/dev/null`; it may stat the dirs above them, so a
//! path resolves; and it execs its program alone. Other operations are as
//! the host's. Every path rides as a profile parameter, resolved as Seatbelt
//! matches it, and is never parsed as profile text.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::spec::OrganSpec;

/// Applies a Seatbelt profile to itself, then execs the program it names.
pub(super) const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// What a program reads to load and run: the system's libraries,
/// frameworks and shared cache, its shared data, configuration and time
/// zones, and the random and zero devices.
const SYSTEM_READ: &[&str] = &[
    "/System/Library",
    "/System/Cryptexes",
    "/System/Volumes/Preboot/Cryptexes",
    "/Library/Apple",
    "/usr/lib",
    "/usr/share",
    "/private/etc",
    "/private/var/db/dyld",
    "/private/var/db/timezone",
    "/dev/random",
    "/dev/urandom",
    "/dev/zero",
];

/// What every fenced organ writes: the system's private temp dir, and the
/// null device its stdio is.
const SYSTEM_WRITE: &[&str] = &["/private/tmp", "/dev/null"];

/// The links into `/private`, which a path given through them stats.
const SYSTEM_LINKS: &[&str] = &["/etc", "/tmp", "/var"];

/// `sandbox-exec` and its arguments: the profile, its parameters, then the
/// organ's program and arguments.
pub(super) fn argv(spec: &OrganSpec) -> (PathBuf, Vec<OsString>) {
    let program = resolved(&spec.program);
    let read: Vec<PathBuf> = spec
        .read_dirs
        .iter()
        .map(PathBuf::as_path)
        .map(resolved)
        .collect();
    let write: Vec<PathBuf> = spec
        .write_dirs
        .iter()
        .map(PathBuf::as_path)
        .map(resolved)
        .collect();
    let system = SYSTEM_READ.iter().chain(SYSTEM_WRITE).map(Path::new);
    let above: BTreeSet<&Path> = [program.as_path()]
        .into_iter()
        .chain(read.iter().map(PathBuf::as_path))
        .chain(write.iter().map(PathBuf::as_path))
        .chain(system)
        .flat_map(|path| path.ancestors().skip(1))
        .collect();
    let mut args = vec![
        OsString::from("-p"),
        OsString::from(profile(read.len(), write.len(), above.len())),
        param("PROGRAM", &program),
    ];
    for (name, paths) in [("READ", &read), ("WRITE", &write)] {
        for (at, path) in paths.iter().enumerate() {
            args.push(param(&format!("{name}_{at}"), path));
        }
    }
    for (at, dir) in above.into_iter().enumerate() {
        args.push(param(&format!("ABOVE_{at}"), dir));
    }
    args.push(OsString::from("--"));
    args.push(program.into_os_string());
    args.extend_from_slice(&spec.args);
    (PathBuf::from(SANDBOX_EXEC), args)
}

/// The profile for `read`, `write` and `above` parameters of each name:
/// file operations denied but on the paths they name, and no exec but the
/// organ's program. A later rule wins over an earlier one.
fn profile(read: usize, write: usize, above: usize) -> String {
    let fixed = |paths: &[&str], filter: &str| -> String {
        paths
            .iter()
            .map(|path| format!(" ({filter} \"{path}\")"))
            .collect()
    };
    let named = |name: &str, count: usize, filter: &str| -> String {
        (0..count)
            .map(|at| format!(" ({filter} (param \"{name}_{at}\"))"))
            .collect()
    };
    let program = " (literal (param \"PROGRAM\"))";
    let reads = format!(
        "{}{program}{}",
        fixed(SYSTEM_READ, "subpath"),
        named("READ", read, "subpath")
    );
    let writes = format!(
        "{}{}",
        fixed(SYSTEM_WRITE, "subpath"),
        named("WRITE", write, "subpath")
    );
    let stats = format!(
        "{}{}",
        fixed(SYSTEM_LINKS, "literal"),
        named("ABOVE", above, "literal")
    );
    format!(
        "(version 1)\n\
         (allow default)\n\
         (deny file*)\n\
         (deny process-exec)\n\
         (allow process-exec{program})\n\
         (allow file-read-metadata{stats})\n\
         (allow file-read*{reads}{writes})\n\
         (allow file-map-executable{reads})\n\
         (allow file-write*{writes})\n"
    )
}

/// `-D<name>=<path>`: one profile parameter.
fn param(name: &str, path: &Path) -> OsString {
    let mut arg = OsString::from(format!("-D{name}="));
    arg.push(path);
    arg
}

/// `path` as Seatbelt matches it, its links resolved (`/var` is
/// `/private/var`); as given where it does not resolve.
fn resolved(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}
