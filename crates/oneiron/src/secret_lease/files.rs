//! T2 file policy, owner-only write, the armed cleanup guard, and teardown.
//!
//! Custody follows the file the vault wrote, not the path string (C9). On
//! unix the target's directory is reached one component at a time through
//! descriptors that never follow a symlink, the file is opened relative to
//! that directory, and its device and inode are recorded on the registration
//! row. Re-materialization writes only into that same file, and teardown
//! unlinks only that same file, and only while it has no other name. Anything
//! else at the name is refused and left in place. A second walk after the
//! open refuses a write whose directory has left the path meanwhile.

use std::fs;
use std::path::Path;

use super::types::FileIdentity;
use crate::error::{Error, Result, SecretError};

fn refused(path: &Path, reason: &'static str) -> Error {
    Error::Secret(SecretError::SecretLeasePathRefused {
        path: path.display().to_string(),
        reason,
    })
}

/// Names what occupies `path` after an open or create refused it. Only the
/// refusal's reason is read from the path; the operation has already failed
/// closed. `file_reason` names a regular file that was already there.
#[cfg(unix)]
fn refuse_occupant(path: &Path, error: std::io::Error, file_reason: &'static str) -> Error {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            refused(path, "target is a symlink (the vault never follows)")
        }
        Ok(metadata) if !metadata.file_type().is_file() => {
            refused(path, "target exists and is not a regular file")
        }
        Ok(_) if error.kind() == std::io::ErrorKind::AlreadyExists => refused(path, file_reason),
        _ => error.into(),
    }
}

// ---------------------------------------------------------------------------
// T2 file lifecycle (SOL-1920-03, C9)
// ---------------------------------------------------------------------------

/// The cleanup guard for a T2 file written by THIS registration attempt.
/// Armed at creation; [`SecretFileGuard::disarm`] runs only after the
/// registration commits durable. A drop while armed removes the file ONLY
/// when `fresh` — created by this attempt, so no durable row records its
/// identity, and a failed row write, lease write, or commit never strands
/// plaintext no row can clean. The removal is the identity-checked one
/// teardown uses. A replace that wrote into the registered file is never the
/// guard's to remove: the live registration row still covers it.
pub(super) struct SecretFileGuard {
    #[cfg(unix)]
    target: written::Target,
    #[cfg(not(unix))]
    path: std::path::PathBuf,
    identity: FileIdentity,
    fresh: bool,
    armed: bool,
}

impl std::fmt::Debug for SecretFileGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretFileGuard")
            .field("identity", &self.identity)
            .field("fresh", &self.fresh)
            .field("armed", &self.armed)
            .finish_non_exhaustive()
    }
}

impl SecretFileGuard {
    /// The identity of the file this attempt wrote, for the registration row.
    pub(super) fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// The registration committed durable: the row owns the file now.
    pub(super) fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for SecretFileGuard {
    fn drop(&mut self) {
        if self.armed && self.fresh {
            // No row will cover this file, so its name goes even when a
            // second name was linked to it meanwhile.
            #[cfg(unix)]
            let _ = self.target.remove(self.identity, written::Links::Any);
            #[cfg(not(unix))]
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Writes the value file for a T2 registration and returns its armed guard.
///
/// `registered` is the identity the lease's live registration row holds:
/// `None` for a fresh registration, which creates the file and never clobbers
/// an occupant; `Some` for same-path re-materialization, which writes only
/// into that file. A registered file that is gone is created again (S4
/// recovery) and gets a new identity; an occupant that is not the registered
/// file, or that file under a second name (a hard link would receive the
/// value too), is refused before any byte lands.
///
/// Owner-only permissions BEFORE the first byte: creation carries
/// `mode(0o600)` (the umask can only narrow), and a replace re-asserts the
/// mode through the open handle (fchmod) ahead of the new bytes. The file
/// holds plaintext and the vault's at-rest DEK plane does not extend to the
/// filesystem, so the declared path gets the tightest default the platform
/// gives us.
#[cfg(unix)]
pub(super) fn write_secret_file(
    target_path: &Path,
    value: &[u8],
    registered: Option<FileIdentity>,
) -> Result<SecretFileGuard> {
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let target = written::Target::open(target_path)?;
    #[cfg(test)]
    path_swap_hook::fire();
    let (mut file, fresh) = match registered {
        None => match target.create() {
            Ok(file) => (file, true),
            Err(error) => {
                return Err(refuse_occupant(
                    target_path,
                    error,
                    "target file exists with no live registration under this lease",
                ));
            }
        },
        Some(expected) => match target.open_for_write() {
            Ok(file) => {
                let metadata = file.metadata()?;
                if !metadata.is_file()
                    || FileIdentity::of(&metadata) != expected
                    || metadata.nlink() != 1
                {
                    return Err(refused(
                        target_path,
                        "target is not the file this lease registered",
                    ));
                }
                (file, false)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // The registered file is lost: S4 recovery writes it anew.
                match target.create() {
                    Ok(file) => (file, true),
                    Err(error) => {
                        return Err(refuse_occupant(
                            target_path,
                            error,
                            "target is not the file this lease registered",
                        ));
                    }
                }
            }
            Err(error) => {
                return Err(refuse_occupant(
                    target_path,
                    error,
                    "target is not the file this lease registered",
                ));
            }
        },
    };
    let identity = FileIdentity::of(&file.metadata()?);
    let guard = SecretFileGuard {
        target,
        identity,
        fresh,
        armed: true,
    };
    // The post-open floor: walk the path again. An ancestor moved or swapped
    // since the first walk leaves the held directory off the stored path, so
    // nothing is written there and a file this attempt created goes with the
    // guard.
    if !guard.target.still_named_by(target_path)? {
        return Err(refused(
            target_path,
            "an ancestor of the target moved while it was written",
        ));
    }
    if !fresh {
        // fchmod also fails on a file another user owns, so an inode number
        // reused under another owner is refused here too.
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.set_len(0)?;
    }
    #[cfg(test)]
    if file_write_fault_hook::take_file_write_failure() {
        return Err(std::io::Error::other("injected file-write failure").into());
    }
    file.write_all(value)?;
    file.flush()?;
    Ok(guard)
}

/// Removes the registered T2 file: `Ok` when it is gone (removed now, or
/// already absent), an error when it could not be removed, when something
/// other than the registered file answers to the path, or when the registered
/// file has another name. A refused occupant is left as it is, so the row
/// keeps covering a file whose plaintext would outlive the unlink.
#[cfg(unix)]
pub(super) fn remove_secret_file(target_path: &Path, registered: FileIdentity) -> Result<()> {
    let target = match written::Target::open(target_path) {
        Ok(target) => target,
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    match target.remove(registered, written::Links::Sole) {
        Ok(None) => Ok(()),
        Ok(Some(reason)) => Err(refused(target_path, reason)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
mod written {
    //! Descriptor-relative access to a T2 target.

    use std::ffi::{CString, OsStr};
    use std::fs::File;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Component, Path, PathBuf};

    use super::{FileIdentity, refused};
    use crate::error::Result;

    /// A T2 target held by descriptor: its directory, and the file's name in it.
    pub(super) struct Target {
        dir: File,
        leaf: CString,
    }

    /// How many names the file may have when [`Target::remove`] unlinks it.
    #[derive(Clone, Copy)]
    pub(super) enum Links {
        /// Only the target's: another name would keep the plaintext after the
        /// unlink, so the file stays and its row keeps covering it.
        Sole,
        /// Any: a file no row will cover loses the target's name regardless.
        Any,
    }

    impl Target {
        /// Walks to the target's directory one component at a time, each
        /// opened through the descriptor of the one before with `O_NOFOLLOW`.
        /// No ancestor is resolved by path after this, so swapping one for a
        /// symlink later moves nothing the vault writes; a symlink met during
        /// the walk is refused. A `..` component is refused too: it asks the
        /// held directory for its current parent, which a rename can change.
        pub(super) fn open(target_path: &Path) -> Result<Self> {
            let leaf = match target_path.file_name() {
                Some(name) => c_name(target_path, name)?,
                None => return Err(refused(target_path, "target names no file")),
            };
            let mut walked = PathBuf::new();
            let mut dir: Option<File> = None;
            for component in target_path.parent().unwrap_or(Path::new("")).components() {
                let name = match component {
                    Component::RootDir => {
                        walked.push(component);
                        dir = Some(open_directory(None, c"/")?);
                        continue;
                    }
                    Component::CurDir => continue,
                    Component::ParentDir => {
                        return Err(refused(target_path, "target path climbs with '..'"));
                    }
                    Component::Normal(_) | Component::Prefix(_) => component.as_os_str(),
                };
                walked.push(name);
                let opened = open_directory(dir.as_ref(), &c_name(&walked, name)?);
                dir = Some(opened.map_err(|error| refuse_ancestor(&walked, error))?);
            }
            let dir = match dir {
                Some(dir) => dir,
                None => open_directory(None, c".")?,
            };
            Ok(Self { dir, leaf })
        }

        /// Whether a fresh walk of `target_path` still reaches the directory
        /// this target holds. A directory gone from the path is not.
        pub(super) fn still_named_by(&self, target_path: &Path) -> Result<bool> {
            let again = match Self::open(target_path) {
                Ok(again) => again,
                Err(crate::error::Error::Io(error))
                    if error.kind() == std::io::ErrorKind::NotFound =>
                {
                    return Ok(false);
                }
                Err(error) => return Err(error),
            };
            Ok(FileIdentity::of(&again.dir.metadata()?) == FileIdentity::of(&self.dir.metadata()?))
        }

        /// Creates the file, never through or over an occupant.
        pub(super) fn create(&self) -> std::io::Result<File> {
            self.open_leaf(libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)
        }

        /// Opens an existing file for writing without truncating it, so its
        /// identity is checked before any byte changes. `O_NONBLOCK` keeps a
        /// planted FIFO from parking the writer.
        pub(super) fn open_for_write(&self) -> std::io::Result<File> {
            self.open_leaf(libc::O_WRONLY | libc::O_NONBLOCK)
        }

        /// Unlinks the leaf when it is the file with `identity` and `links`
        /// admits its link count. `Ok(Some(reason))` leaves the occupant in
        /// place. The leaf is checked through the held directory and unlinked
        /// from it, so only a process that swaps the leaf itself between the
        /// check and the unlink is outside this check.
        pub(super) fn remove(
            &self,
            identity: FileIdentity,
            links: Links,
        ) -> std::io::Result<Option<&'static str>> {
            const SUBSTITUTED: &str = "target is not the file this lease registered";
            let occupant = match self.open_leaf(libc::O_RDONLY | libc::O_NONBLOCK) {
                Ok(file) => file.metadata()?,
                Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
                    return Ok(Some(SUBSTITUTED));
                }
                Err(error) => return Err(error),
            };
            if !occupant.is_file() || FileIdentity::of(&occupant) != identity {
                return Ok(Some(SUBSTITUTED));
            }
            if matches!(links, Links::Sole) && occupant.nlink() != 1 {
                return Ok(Some("the registered file has another name"));
            }
            // SAFETY: `self.dir` holds a live directory descriptor and
            // `self.leaf` is a NUL-terminated single component that lives
            // through the call; unlinkat transfers no descriptor ownership.
            if unsafe { libc::unlinkat(self.dir.as_raw_fd(), self.leaf.as_ptr(), 0) } < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(None)
        }

        fn open_leaf(&self, flags: libc::c_int) -> std::io::Result<File> {
            // SAFETY: `self.dir` holds a live directory descriptor and
            // `self.leaf` is a NUL-terminated single component that lives
            // through the call; `adopt` owns only a successfully opened fd.
            let fd = unsafe {
                libc::openat(
                    self.dir.as_raw_fd(),
                    self.leaf.as_ptr(),
                    flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    0o600,
                )
            };
            adopt(fd)
        }
    }

    /// A symlinked ancestor is the refusal; any other failure is the open's.
    fn refuse_ancestor(walked: &Path, error: std::io::Error) -> crate::error::Error {
        match std::fs::symlink_metadata(walked) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                refused(walked, "ancestor is a symlink (the vault never follows)")
            }
            _ => error.into(),
        }
    }

    fn c_name(path: &Path, name: &OsStr) -> Result<CString> {
        CString::new(name.as_bytes()).map_err(|_| refused(path, "target path contains a NUL byte"))
    }

    /// Opens one directory component relative to `at` (the working directory
    /// when `None`), never following a symlink.
    fn open_directory(at: Option<&File>, name: &std::ffi::CStr) -> std::io::Result<File> {
        let at = at.map_or(libc::AT_FDCWD, AsRawFd::as_raw_fd);
        // SAFETY: `at` is AT_FDCWD or a live directory descriptor borrowed for
        // this call, and `name` is NUL-terminated and lives through it;
        // `adopt` owns only a successfully opened fd.
        let fd = unsafe {
            libc::openat(
                at,
                name.as_ptr(),
                libc::O_DIRECTORY | libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        adopt(fd)
    }

    fn adopt(fd: libc::c_int) -> std::io::Result<File> {
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` is a non-negative descriptor just returned by `openat`
        // and held by no other owner, so this `File` closes it exactly once.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

/// The non-unix fallback: path-based, with the symlink policy checked before
/// the open and the same no-clobber create. The platform gives no owner-only
/// mode, no no-follow open, and no file identity, so a registration there
/// records none, an ancestor swapped after the check is not caught, and
/// teardown removes by path.
#[cfg(not(unix))]
pub(super) fn write_secret_file(
    target_path: &Path,
    value: &[u8],
    registered: Option<FileIdentity>,
) -> Result<SecretFileGuard> {
    use std::io::Write;

    for ancestor in target_path.ancestors().skip(1) {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(refused(
                    ancestor,
                    "ancestor is a symlink (the vault never follows)",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    match fs::symlink_metadata(target_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(refused(
                target_path,
                "target is a symlink (the vault never follows)",
            ));
        }
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(refused(
                target_path,
                "target exists and is not a regular file",
            ));
        }
        Ok(_) if registered.is_none() => {
            return Err(refused(
                target_path,
                "target file exists with no live registration under this lease",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut options = fs::OpenOptions::new();
    options.write(true);
    if registered.is_some() {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    let mut file = options.open(target_path)?;
    let guard = SecretFileGuard {
        path: target_path.to_path_buf(),
        identity: FileIdentity::UNBOUND,
        fresh: registered.is_none(),
        armed: true,
    };
    #[cfg(test)]
    if file_write_fault_hook::take_file_write_failure() {
        return Err(std::io::Error::other("injected file-write failure").into());
    }
    file.write_all(value)?;
    file.flush()?;
    Ok(guard)
}

/// The non-unix teardown: removes by path.
#[cfg(not(unix))]
pub(super) fn remove_secret_file(target_path: &Path, _registered: FileIdentity) -> Result<()> {
    match fs::remove_file(target_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
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

#[cfg(all(test, unix))]
pub(super) mod path_swap_hook {
    //! One-shot test-only seam between resolving a T2 target's directory and
    //! opening its file: the window a racing local process would use to swap
    //! an ancestor for a symlink.

    use std::cell::RefCell;

    type Swap = Box<dyn FnOnce()>;

    thread_local! {
        static SWAP: RefCell<Option<Swap>> = const { RefCell::new(None) };
    }

    /// Runs `swap` once, at the next T2 file write on this thread.
    pub(in crate::secret_lease) fn arm(swap: impl FnOnce() + 'static) {
        SWAP.with_borrow_mut(|armed| *armed = Some(Box::new(swap)));
    }

    pub(super) fn fire() {
        if let Some(swap) = SWAP.with_borrow_mut(Option::take) {
            swap();
        }
    }
}
