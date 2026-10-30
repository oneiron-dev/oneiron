//! The filesystem fence on macOS (FIX 7885, ARCH-0075): a third-party organ
//! starts through Seatbelt's `sandbox-exec`, under a profile that denies
//! every operation but these. The system's own process rules come from
//! `system.sb`, the base Apple's own deny-default profiles import: what
//! dyld needs to load a program (the system's libraries, frameworks and
//! shared cache), the system's configuration, time zones and devices, its
//! sysctls and its logging and directory services. Beside those the organ
//! reads and maps its program and its spec's read dirs, reads and writes
//! its own scratch dir (`scratch`), stats the dirs above them so a path
//! resolves, execs its program alone, forks, signals what it forked, and
//! makes and maps its regions (POSIX shared memory under the protocol's
//! names). It has no network, and no other process's arguments or
//! environment. Every path rides as a profile parameter, resolved as
//! Seatbelt matches it, and is never parsed as profile text.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::spec::OrganSpec;

/// Applies a Seatbelt profile to itself, then execs the program it names.
pub(super) const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// How the organ protocol names a POSIX shared-memory region it makes on
/// macOS (`oneiron_organ_protocol::SharedRegion`).
const REGION_NAMES: &str = "/onr.";

/// `sandbox-exec` and its arguments: the profile, its parameters, then the
/// organ's program and arguments. `scratch` is the organ's scratch dir.
pub(super) fn argv(spec: &OrganSpec, scratch: &Path) -> (PathBuf, Vec<OsString>) {
    let program = resolved(&spec.program);
    let read: Vec<PathBuf> = spec
        .read_dirs
        .iter()
        .map(PathBuf::as_path)
        .map(resolved)
        .collect();
    let above: BTreeSet<&Path> = [program.as_path(), scratch]
        .into_iter()
        .chain(read.iter().map(PathBuf::as_path))
        .flat_map(|path| path.ancestors().skip(1))
        .collect();
    let mut args = vec![
        OsString::from("-p"),
        OsString::from(profile(read.len(), above.len())),
        param("PROGRAM", &program),
        param("SCRATCH", scratch),
    ];
    for (at, path) in read.iter().enumerate() {
        args.push(param(&format!("READ_{at}"), path));
    }
    for (at, dir) in above.into_iter().enumerate() {
        args.push(param(&format!("ABOVE_{at}"), dir));
    }
    args.push(OsString::from("--"));
    args.push(program.into_os_string());
    args.extend_from_slice(&spec.args);
    (PathBuf::from(SANDBOX_EXEC), args)
}

/// The profile for `read` and `above` parameters of each name. A later rule
/// wins over an earlier one, so the denials after `system.sb` narrow it:
/// its syslog socket goes with the network, and the `kern.procargs`
/// sysctls, which hand out another process's arguments and environment,
/// are cut from its sysctls.
fn profile(read: usize, above: usize) -> String {
    let named = |name: &str, count: usize, filter: &str| -> String {
        (0..count)
            .map(|at| format!(" ({filter} (param \"{name}_{at}\"))"))
            .collect()
    };
    let program = " (literal (param \"PROGRAM\"))";
    let scratch = " (subpath (param \"SCRATCH\"))";
    let reads = named("READ", read, "subpath");
    let stats = named("ABOVE", above, "literal");
    format!(
        "(version 1)\n\
         (deny default)\n\
         (import \"system.sb\")\n\
         (deny network*)\n\
         (deny sysctl-read (sysctl-name-prefix \"kern.procargs\"))\n\
         (allow process-fork)\n\
         (allow signal (target same-sandbox))\n\
         (allow process-info* (target self))\n\
         (allow process-codesigning-status* (target self))\n\
         (allow process-exec{program})\n\
         (allow file-read* file-map-executable{program}{reads})\n\
         (allow file-read* file-write*{scratch})\n\
         (allow file-read-metadata{stats})\n\
         (allow ipc-posix-shm* (ipc-posix-name-prefix \"{REGION_NAMES}\"))\n"
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
