//! The filesystem fence on Linux (FIX 7885, ARCH-0075): Landlock, ABI 3 or
//! later. A third-party organ reads and runs the system's programs,
//! libraries and configuration and its own program, reads the random and
//! zero devices and its spec's read dirs, and reads and writes `/dev/null`
//! and its own scratch dir (`scratch`); nothing else. Not `/proc` or `/sys`:
//! the organ shares the engine's user and pid namespace, so
//! `/proc/<pid>/environ` would hand it the engine's secrets. Not `/tmp` or
//! `/dev/shm`: what the engine and other organs leave there is theirs, and
//! a region is a memfd, which no path names. The ruleset is built before the
//! fork; the child restricts itself to it beside `no_new_privs`.

use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use crate::spec::OrganSpec;

/// What every fenced organ reads and runs: the system's programs,
/// libraries and configuration, and the random and zero devices.
const SYSTEM_READ: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/etc",
    "/dev/zero",
    "/dev/urandom",
    "/dev/random",
];

/// What every fenced organ writes besides its scratch dir: the null device
/// its stdio is.
const SYSTEM_WRITE: &[&str] = &["/dev/null"];

/// `spec`'s ruleset, with `scratch` its one dir to write.
///
/// # Errors
/// The kernel's Landlock ABI is below 3, or a rule could not be made; the
/// error says it was the fence.
pub(super) fn ruleset(spec: &OrganSpec, scratch: &Path) -> io::Result<OwnedFd> {
    let mut read: Vec<&Path> = SYSTEM_READ.iter().map(Path::new).collect();
    read.push(spec.program.as_path());
    read.extend(spec.read_dirs.iter().map(PathBuf::as_path));
    let mut write: Vec<&Path> = SYSTEM_WRITE.iter().map(Path::new).collect();
    write.push(scratch);
    oneiron_container::landlock_ruleset(&read, &write).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("the organ's Landlock fence could not be built: {err}"),
        )
    })
}
