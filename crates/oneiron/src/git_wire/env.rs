//! Pinned process baseline: executable resolution, bounds, and the test-only binary override.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use super::GitWireResult;
use super::config::{
    GIT_WIRE_DEFAULT_BINARY, GIT_WIRE_DEFAULT_MAX_OUTPUT_BYTES, GIT_WIRE_DEFAULT_TIMEOUT,
};
use super::failure::invalid;
use crate::error::Result;

/// The pinned executable, inherited baseline, and resource bounds every child
/// runs under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitWireProcessEnv {
    pub(super) git_binary: PathBuf,
    pub(super) path: OsString,
    pub(super) tmpdir: PathBuf,
    pub(super) timeout: Duration,
    pub(super) max_output_bytes: usize,
}

/// The process baseline, resolved once. Pinning the executable at first use is
/// what keeps a later `PATH` change from redirecting a child.
static GIT_WIRE_PROCESS_ENV: LazyLock<Option<GitWireProcessEnv>> =
    LazyLock::new(GitWireProcessEnv::resolve);

impl GitWireProcessEnv {
    /// The captured baseline with the git executable pinned to one absolute
    /// path.
    pub fn capture() -> GitWireResult<Self> {
        GIT_WIRE_PROCESS_ENV
            .clone()
            .ok_or_else(|| invalid("git executable was not found on PATH"))
    }

    fn resolve() -> Option<Self> {
        let path = std::env::var_os("PATH").unwrap_or_default();
        let git_binary = resolve_git_binary(&path).ok()?;
        Some(Self {
            git_binary,
            path,
            tmpdir: std::env::temp_dir(),
            timeout: GIT_WIRE_DEFAULT_TIMEOUT,
            max_output_bytes: GIT_WIRE_DEFAULT_MAX_OUTPUT_BYTES,
        })
    }

    /// The pinned absolute git executable.
    pub fn git_binary(&self) -> &Path {
        &self.git_binary
    }

    /// The wall-clock bound on one child.
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// The captured output bound of one child.
    pub const fn max_output_bytes(&self) -> usize {
        self.max_output_bytes
    }

    /// Narrows the runtime and output bounds.
    pub fn with_limits(
        mut self,
        timeout: Duration,
        max_output_bytes: usize,
    ) -> GitWireResult<Self> {
        if timeout.is_zero() || max_output_bytes == 0 {
            return Err(invalid("git wire bounds must be positive"));
        }
        self.timeout = timeout;
        self.max_output_bytes = max_output_bytes;
        Ok(self)
    }

    /// Test-only: retargets the pinned executable so the bounded-runtime and
    /// bounded-output paths can be exercised deterministically. No production
    /// build can reach this, so the boundary keeps exactly one executable.
    #[cfg(test)]
    pub(super) fn with_binary_for_test(mut self, binary: PathBuf) -> Self {
        self.git_binary = binary;
        self
    }
}

fn resolve_git_binary(path: &OsString) -> Result<PathBuf> {
    for directory in std::env::split_paths(path) {
        if directory.as_os_str().is_empty() {
            continue;
        }
        let candidate = directory.join(GIT_WIRE_DEFAULT_BINARY);
        if is_executable_file(&candidate) {
            return candidate
                .canonicalize()
                .map_err(|_| invalid("git executable could not be pinned"));
        }
    }
    Err(invalid("git executable was not found on PATH"))
}

#[cfg(unix)]
fn is_executable_file(candidate: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(candidate)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable_file(candidate: &Path) -> bool {
    matches!(fs::metadata(candidate), Ok(metadata) if metadata.is_file())
}
