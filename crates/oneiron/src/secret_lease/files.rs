//! T2 file policy, owner-only write, and the armed cleanup guard.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// T2 file lifecycle (SOL-1920-03)
// ---------------------------------------------------------------------------

/// The T2 file policy, checked BEFORE any byte lands: the declared target
/// and its existing ancestors are never followed through a symlink, and the
/// vault never clobbers an occupant it did not create under this lease. A
/// regular file already at the target is touched only under `replace` —
/// same-path re-materialization, where this lease's live registration row
/// already covers exactly this path. Anything else denies typed
/// ([`Error::SecretLeasePathRefused`]). Ancestors are checked at policy time;
/// an ancestor swap between this check and open is the same race class as the
/// documented leaf check-to-open race. Race-free traversal needs openat2 or
/// dirfd handling and is intentionally out of scope here.
fn check_secret_file_policy(target_path: &Path, replace: bool) -> Result<()> {
    for ancestor in target_path.ancestors().skip(1) {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(Error::SecretLeasePathRefused {
                    path: ancestor.display().to_string(),
                    reason: "ancestor is a symlink (the vault never follows)",
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }

    let metadata = match fs::symlink_metadata(target_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(Error::SecretLeasePathRefused {
            path: target_path.display().to_string(),
            reason: "target is a symlink (the vault never follows)",
        });
    }
    if !file_type.is_file() {
        return Err(Error::SecretLeasePathRefused {
            path: target_path.display().to_string(),
            reason: "target exists and is not a regular file",
        });
    }
    if !replace {
        return Err(Error::SecretLeasePathRefused {
            path: target_path.display().to_string(),
            reason: "target file exists with no live registration under this lease",
        });
    }
    Ok(())
}

/// The cleanup guard for a T2 file written by THIS registration attempt.
/// Armed at creation; [`SecretFileGuard::disarm`] runs only after the
/// registration commits durable. A drop while armed removes the file ONLY
/// when `fresh` — created by this attempt under a lease with no durable
/// registration for the path, so a failed row write, lease write, or
/// commit never strands plaintext no row can clean. A same-path replace is
/// never the guard's to remove: the live registration row still covers the
/// file, so a failure leaves it (and SECRET-03's exclusion) in place.
#[derive(Debug)]
pub(super) struct SecretFileGuard {
    path: PathBuf,
    fresh: bool,
    armed: bool,
}

impl SecretFileGuard {
    fn new(path: &Path, fresh: bool) -> Self {
        Self {
            path: path.to_path_buf(),
            fresh,
            armed: true,
        }
    }

    /// The registration committed durable: the row owns the file now.
    pub(super) fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for SecretFileGuard {
    fn drop(&mut self) {
        if self.armed && self.fresh {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Writes the value file for a T2 registration under
/// [`check_secret_file_policy`] and returns its armed guard. Owner-only
/// permissions BEFORE the first byte: creation carries `mode(0o600)` (the
/// umask can only narrow), and a replace re-asserts the mode through the
/// open handle (fchmod — no path race) ahead of the new bytes. The file
/// holds plaintext and the vault's at-rest DEK plane does not extend to
/// the filesystem, so the declared path gets the tightest default the
/// platform gives us. `O_NOFOLLOW` underpins the policy check against a
/// check-to-open symlink swap.
#[cfg(unix)]
pub(super) fn write_secret_file(
    target_path: &Path,
    value: &[u8],
    replace: bool,
) -> Result<SecretFileGuard> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::PermissionsExt;

    check_secret_file_policy(target_path, replace)?;
    let mut options = fs::OpenOptions::new();
    options
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW);
    if replace {
        // Same-path re-materialization: truncate the file this lease's
        // registration covers, or recreate it when lost (S4 recovery).
        options.create(true).truncate(true);
    } else {
        // Fresh registration: create_new is the atomic no-clobber guard —
        // anything that appeared at the target after the policy check
        // fails the open instead of being overwritten.
        options.create_new(true);
    }
    let mut file = options.open(target_path)?;
    let guard = SecretFileGuard::new(target_path, !replace);
    if replace {
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(test)]
    if file_write_fault_hook::take_file_write_failure() {
        return Err(std::io::Error::other("injected file-write failure").into());
    }
    file.write_all(value)?;
    file.flush()?;
    Ok(guard)
}

/// The non-unix fallback: the same policy and no-clobber create; the
/// platform gives no owner-only mode or no-follow open flag.
#[cfg(not(unix))]
pub(super) fn write_secret_file(
    target_path: &Path,
    value: &[u8],
    replace: bool,
) -> Result<SecretFileGuard> {
    use std::io::Write;

    check_secret_file_policy(target_path, replace)?;
    let mut options = fs::OpenOptions::new();
    options.write(true);
    if replace {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    let mut file = options.open(target_path)?;
    let guard = SecretFileGuard::new(target_path, !replace);
    #[cfg(test)]
    if file_write_fault_hook::take_file_write_failure() {
        return Err(std::io::Error::other("injected file-write failure").into());
    }
    file.write_all(value)?;
    file.flush()?;
    Ok(guard)
}

#[cfg(test)]
pub(super) mod file_write_fault_hook {
    //! One-shot test-only fault injection after the T2 file opens, proving
    //! the guard is armed before a file write can fail.

    use std::cell::Cell;

    thread_local! {
        static FILE_WRITE_FAILURE: Cell<bool> = const { Cell::new(false) };
    }

    /// Arms a one-shot file-write failure on the current thread.
    pub(in crate::secret_lease) fn arm_file_write_failure() {
        FILE_WRITE_FAILURE.with(|c| c.set(true));
    }

    /// Returns and clears the armed flag (one-shot).
    pub(super) fn take_file_write_failure() -> bool {
        FILE_WRITE_FAILURE.with(|c| c.replace(false))
    }
}
