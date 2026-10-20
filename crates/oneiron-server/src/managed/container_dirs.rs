//! The host directories the supervisor binds for the guests' container CLI
//! (`--container-home` and `--container-runtime-dir`, FIX 6876): the `HOME`
//! and `XDG_RUNTIME_DIR` it runs with, so a rootless CLI started under the
//! vault's UID finds its per-UID storage and runtime state.
//!
//! Each is checked on its own once tracing runs: an absolute path with no
//! `..` part, a directory that exists, owned by this process's effective
//! UID. One that fails is ignored with a warning, never a refused start, and
//! the CLI runs without it, as it does when the flag is absent. Nothing here
//! makes a directory or sets a mode: the supervisor provisions both. Only
//! the CLI's own environment gets them
//! ([`oneiron_container::set_cli_env`]); the engine's environment and
//! configuration do not change.

use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

use super::args::ManagedArgs;

/// The reason token of the notice that a container CLI directory the
/// supervisor passed failed its check and is ignored.
const CONTAINER_DIR_IGNORED: &str = "container_dir_ignored";

/// Why a container CLI directory is ignored, in closed names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ignored {
    /// The path is not absolute.
    NotAbsolute,
    /// It holds a `..` part.
    ParentComponent,
    /// Nothing is there.
    Missing,
    /// It is not a directory.
    NotDirectory,
    /// Another UID than this process's effective one owns it.
    NotOwned,
    /// It did not read for another reason than a missing part.
    Unreadable,
    /// This platform has no owner to check.
    #[cfg(not(unix))]
    Unsupported,
}

impl Ignored {
    /// The wire spelling, for a log field.
    const fn as_str(self) -> &'static str {
        match self {
            Self::NotAbsolute => "not_absolute",
            Self::ParentComponent => "parent_component",
            Self::Missing => "missing",
            Self::NotDirectory => "not_directory",
            Self::NotOwned => "not_owned",
            Self::Unreadable => "unreadable",
            #[cfg(not(unix))]
            Self::Unsupported => "unsupported",
        }
    }
}

/// Checks the container CLI's directories `managed` names and binds the
/// ones that pass as its `HOME` and `XDG_RUNTIME_DIR` for this process. One
/// that fails is logged with its flag and cause and left out.
pub(super) fn bind_container_cli_env(managed: &ManagedArgs) {
    let [home, runtime_dir] = [
        ("container-home", managed.container_home.as_deref()),
        (
            "container-runtime-dir",
            managed.container_runtime_dir.as_deref(),
        ),
    ]
    .map(|(flag, declared)| {
        let declared = declared?;
        check(declared)
            .inspect_err(|cause| {
                tracing::warn!(
                    reason = CONTAINER_DIR_IGNORED,
                    flag,
                    cause = cause.as_str(),
                    dir = %declared.display(),
                    "a container CLI directory the supervisor passed failed its check and is ignored: the container CLI runs without it"
                );
            })
            .ok()
    });
    oneiron_container::set_cli_env(home, runtime_dir);
}

/// Checks one declared directory: absolute with no `..` part, a directory
/// once its links are followed, and owned by this process's effective UID.
fn check(declared: &Path) -> Result<PathBuf, Ignored> {
    if !declared.is_absolute() {
        return Err(Ignored::NotAbsolute);
    }
    if declared
        .components()
        .any(|part| part == Component::ParentDir)
    {
        return Err(Ignored::ParentComponent);
    }
    let meta = std::fs::metadata(declared).map_err(|error| match error.kind() {
        ErrorKind::NotFound | ErrorKind::NotADirectory => Ignored::Missing,
        _ => Ignored::Unreadable,
    })?;
    if !meta.is_dir() {
        return Err(Ignored::NotDirectory);
    }
    owned(&meta)?;
    Ok(declared.to_path_buf())
}

/// Whether this process's effective UID owns the directory.
#[cfg(unix)]
fn owned(meta: &std::fs::Metadata) -> Result<(), Ignored> {
    use std::os::unix::fs::MetadataExt as _;
    if meta.uid() == rustix::process::geteuid().as_raw() {
        Ok(())
    } else {
        Err(Ignored::NotOwned)
    }
}

/// No owner to check here, so the directory is ignored.
#[cfg(not(unix))]
fn owned(_meta: &std::fs::Metadata) -> Result<(), Ignored> {
    Err(Ignored::Unsupported)
}
