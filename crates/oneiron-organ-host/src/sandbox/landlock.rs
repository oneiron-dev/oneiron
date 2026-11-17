//! The filesystem fence on Linux (FIX 7885, ARCH-0075): Landlock, ABI 3 or
//! later. A fenced organ reads and runs the system's programs, libraries
//! and configuration and its own program, reads the random and zero
//! devices and its spec's read dirs, and reads and writes `/dev/null`;
//! besides those a third-party organ reads and writes its own scratch dir
//! (`scratch`), and a first-party organ its spec's write dirs, which no
//! organ the engine installs names; nothing else. Not `/proc` or `/sys`:
//! the organ runs as the engine's uid, so `/proc/<pid>/environ` would hand
//! it the engine's secrets, and `/proc/<pid>/oom_score_adj` would let it
//! make the engine the kernel's first kill. Not `/tmp` or `/dev/shm`: what
//! the engine and other organs leave there is theirs, and a region is a
//! memfd, which no path names. Nor the vault's files, whose locks an organ
//! could hold against the engine. The ruleset is built before the fork; the
//! child restricts itself to it beside `no_new_privs`.
//!
//! A third-party organ always starts fenced, and a host with no Landlock
//! refuses it. A first-party organ starts fenced where the kernel has
//! Landlock ABI 3 (FIX [FIRST-PARTY-ORGAN-PROC-REACH]) and unfenced where
//! it has none, on the protections that are built (ARCH-0075).

use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use crate::spec::{OrganSpec, OrganTier};

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

/// What every fenced organ writes: the null device its stdio is.
const SYSTEM_WRITE: &[&str] = &["/dev/null"];

/// The ruleset `spec`'s organ starts under: a third-party organ's, with
/// `scratch` its one dir to write; a first-party organ's, with its spec's
/// write dirs, where the kernel has Landlock ABI 3
/// ([`super::filesystem_confined`]); `None` for a first-party organ on a
/// kernel with none.
///
/// # Errors
/// A rule could not be made, a third-party organ's kernel has no Landlock
/// ABI 3, or a third-party organ has no scratch dir; the error says it was
/// the fence.
pub(super) fn fence(spec: &OrganSpec, scratch: Option<&Path>) -> io::Result<Option<OwnedFd>> {
    match spec.tier {
        OrganTier::ThirdParty => {
            let scratch = scratch.ok_or_else(|| {
                io::Error::other("the organ's Landlock fence could not be built: no scratch dir")
            })?;
            ruleset(spec, &[scratch]).map(Some)
        }
        OrganTier::FirstParty if super::filesystem_confined() => {
            let write: Vec<&Path> = spec.write_dirs.iter().map(PathBuf::as_path).collect();
            ruleset(spec, &write).map(Some)
        }
        OrganTier::FirstParty => Ok(None),
    }
}

/// `spec`'s ruleset, with `write` the dirs it writes besides the null
/// device.
fn ruleset(spec: &OrganSpec, write: &[&Path]) -> io::Result<OwnedFd> {
    let mut read: Vec<&Path> = SYSTEM_READ.iter().map(Path::new).collect();
    read.push(spec.program.as_path());
    read.extend(spec.read_dirs.iter().map(PathBuf::as_path));
    let mut writes: Vec<&Path> = SYSTEM_WRITE.iter().map(Path::new).collect();
    writes.extend_from_slice(write);
    oneiron_container::landlock_ruleset(&read, &writes).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("the organ's Landlock fence could not be built: {err}"),
        )
    })
}
