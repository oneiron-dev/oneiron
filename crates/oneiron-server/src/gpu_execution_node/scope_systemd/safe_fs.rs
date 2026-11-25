//! File operations for the unit's root steps in directories another
//! account owns (the engine's state and payload directories). Every name is
//! opened beneath a directory descriptor, never through a link, and a file
//! is replaced only by a rename inside its own directory: a link the engine
//! planted can make a root step fail, never write elsewhere.

use std::ffi::{CString, OsStr};
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

/// What `fstat` says of an open file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileFacts {
    pub uid: u32,
    pub gid: u32,
    /// The permission bits, with set-id and sticky bits.
    pub mode: u32,
    pub is_dir: bool,
    pub is_regular: bool,
    pub is_fifo: bool,
    pub size: u64,
}

fn c_name(name: &OsStr) -> io::Result<CString> {
    if name.is_empty() || name.as_bytes().contains(&b'/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a name beneath a directory is one path segment",
        ));
    }
    CString::new(name.as_bytes())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

fn owned(fd: libc::c_int) -> io::Result<OwnedFd> {
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the caller passes a descriptor the kernel just returned.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn check(answer: libc::c_int) -> io::Result<()> {
    if answer < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// `fstat` of `fd`.
///
/// # Errors
///
/// The kernel refused it.
pub fn facts(fd: BorrowedFd<'_>) -> io::Result<FileFacts> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat fills the whole buffer when it succeeds.
    check(unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) })?;
    // SAFETY: fstat succeeded.
    let stat = unsafe { stat.assume_init() };
    let kind = stat.st_mode & libc::S_IFMT;
    Ok(FileFacts {
        uid: stat.st_uid,
        gid: stat.st_gid,
        mode: stat.st_mode & 0o7777,
        is_dir: kind == libc::S_IFDIR,
        is_regular: kind == libc::S_IFREG,
        is_fifo: kind == libc::S_IFIFO,
        size: u64::try_from(stat.st_size).unwrap_or(0),
    })
}

/// The directory `name` beneath `dir` (or the absolute path's first step
/// when `dir` is `None` and `name` is `/`), opened as a directory and never
/// through a link.
///
/// # Errors
///
/// The open failed: a link, not a directory, absent.
pub fn open_dir_beneath(dir: BorrowedFd<'_>, name: &OsStr) -> io::Result<OwnedFd> {
    let name = c_name(name)?;
    // SAFETY: name is NUL terminated; the flags open a directory handle only.
    owned(unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    })
}

/// An absolute directory, opened one component at a time and never through
/// a link.
///
/// # Errors
///
/// A relative path, a `..`, a link on the way, or a failed open.
pub fn open_dir_path(path: &Path) -> io::Result<OwnedFd> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{}: not an absolute path", path.display()),
        ));
    }
    let root = CString::new("/").map_err(io::Error::other)?;
    // SAFETY: the literal is NUL terminated.
    let mut current = owned(unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    })?;
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                current = open_dir_beneath(borrow(&current), name).map_err(|error| {
                    io::Error::new(error.kind(), format!("{}: {error}", path.display()))
                })?;
            }
            Component::ParentDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{}: a path with '..'", path.display()),
                ));
            }
        }
    }
    Ok(current)
}

/// Borrows an owned descriptor.
#[must_use]
pub fn borrow(fd: &OwnedFd) -> BorrowedFd<'_> {
    use std::os::fd::AsFd as _;
    fd.as_fd()
}

/// Reads the regular file `name` beneath `dir`, at most `max` bytes, never
/// through a link, and, with `owner`, only a file that account owns.
/// `Ok(None)` when it does not exist.
///
/// # Errors
///
/// A link, not a regular file, another owner, larger than `max`, or a
/// failed read.
pub fn read_beneath(
    dir: BorrowedFd<'_>,
    name: &str,
    max: u64,
    owner: Option<u32>,
) -> io::Result<Option<Vec<u8>>> {
    use std::io::Read as _;
    let c = c_name(OsStr::new(name))?;
    // SAFETY: c is NUL terminated; O_NOFOLLOW refuses a link.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    let fd = match owned(fd) {
        Ok(fd) => fd,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let found = facts(borrow(&fd))?;
    if !found.is_regular {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{name} is not a regular file"),
        ));
    }
    if let Some(uid) = owner
        && found.uid != uid
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{name} is owned by uid {}, not uid {uid}", found.uid),
        ));
    }
    if found.size > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{name} is larger than {max} bytes"),
        ));
    }
    let mut bytes = Vec::new();
    std::fs::File::from(fd)
        .take(max.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{name} grew past {max} bytes"),
        ));
    }
    Ok(Some(bytes))
}

/// Writes `bytes` to `name` beneath `dir`: a fresh `<name>.new` (any old
/// one, link or not, is unlinked first), synced, owned by `owner` when
/// given, with `mode`, then renamed over `name` and the directory synced.
///
/// # Errors
///
/// The step that failed.
pub fn write_beneath(
    dir: BorrowedFd<'_>,
    name: &str,
    bytes: &[u8],
    mode: u32,
    owner: Option<(u32, u32)>,
) -> io::Result<()> {
    use std::io::Write as _;
    let staging = format!("{name}.new");
    let c_staging = c_name(OsStr::new(&staging))?;
    let c_final = c_name(OsStr::new(name))?;
    // SAFETY: c_staging is NUL terminated; unlinkat removes a link itself.
    let removed = unsafe { libc::unlinkat(dir.as_raw_fd(), c_staging.as_ptr(), 0) };
    if removed < 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::NotFound {
            return Err(error);
        }
    }
    // SAFETY: c_staging is NUL terminated; O_EXCL with O_NOFOLLOW makes a new
    // file or fails.
    let fd = owned(unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c_staging.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode as libc::c_uint,
        )
    })?;
    if let Some((uid, gid)) = owner {
        // SAFETY: fd is the file this call made.
        check(unsafe { libc::fchown(fd.as_raw_fd(), uid, gid) })?;
    }
    // SAFETY: fd is the file this call made; fchmod sets the mode the umask
    // may have narrowed.
    check(unsafe { libc::fchmod(fd.as_raw_fd(), mode as libc::mode_t) })?;
    let mut file = std::fs::File::from(fd);
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    // SAFETY: both names are NUL terminated and beneath the same directory.
    check(unsafe {
        libc::renameat(
            dir.as_raw_fd(),
            c_staging.as_ptr(),
            dir.as_raw_fd(),
            c_final.as_ptr(),
        )
    })?;
    // SAFETY: dir is an open directory.
    check(unsafe { libc::fsync(dir.as_raw_fd()) })
}

/// Makes the directory `name` beneath `dir`, owned by `owner` with `mode`,
/// and returns it open. It must not exist yet.
///
/// # Errors
///
/// It exists (anything at that name), or a step failed.
pub fn make_dir_beneath(
    dir: BorrowedFd<'_>,
    name: &str,
    mode: u32,
    owner: (u32, u32),
) -> io::Result<OwnedFd> {
    let c = c_name(OsStr::new(name))?;
    // SAFETY: c is NUL terminated.
    check(unsafe { libc::mkdirat(dir.as_raw_fd(), c.as_ptr(), 0o700) })?;
    let made = open_dir_beneath(dir, OsStr::new(name))?;
    // SAFETY: made is the directory this call created and opened.
    check(unsafe { libc::fchown(made.as_raw_fd(), owner.0, owner.1) })?;
    // SAFETY: as above.
    check(unsafe { libc::fchmod(made.as_raw_fd(), mode as libc::mode_t) })?;
    Ok(made)
}

/// Makes the pipe `name` beneath `dir` with `mode` and group `gid`.
///
/// # Errors
///
/// It exists, or a step failed.
pub fn make_fifo_beneath(dir: BorrowedFd<'_>, name: &str, mode: u32, gid: u32) -> io::Result<()> {
    let c = c_name(OsStr::new(name))?;
    // SAFETY: c is NUL terminated.
    check(unsafe { libc::mkfifoat(dir.as_raw_fd(), c.as_ptr(), 0o600) })?;
    // SAFETY: c is NUL terminated; AT_SYMLINK_NOFOLLOW changes no link target.
    check(unsafe {
        libc::fchownat(
            dir.as_raw_fd(),
            c.as_ptr(),
            0,
            gid,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    })?;
    // SAFETY: c is NUL terminated. fchmodat follows no link here: the name
    // was made by this call in a directory only root writes.
    check(unsafe { libc::fchmodat(dir.as_raw_fd(), c.as_ptr(), mode as libc::mode_t, 0) })
}

/// Removes the file `name` beneath `dir`; an absent one is fine.
///
/// # Errors
///
/// The unlink failed for another reason.
pub fn remove_beneath(dir: BorrowedFd<'_>, name: &str) -> io::Result<()> {
    let c = c_name(OsStr::new(name))?;
    // SAFETY: c is NUL terminated.
    let answer = unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), 0) };
    if answer < 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::NotFound {
            return Err(error);
        }
    }
    Ok(())
}

/// Whether `path` and every directory above it are owned by root and
/// writable by no one else, so no other account can change what a root step
/// reads there.
///
/// # Errors
///
/// The first path that is not, and why.
pub fn require_root_owned(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;
    let mut current = Some(path);
    while let Some(step) = current {
        let meta = std::fs::symlink_metadata(step)
            .map_err(|error| format!("{}: {error}", step.display()))?;
        if meta.file_type().is_symlink() {
            return Err(format!("{}: a link; give the real path", step.display()));
        }
        if meta.uid() != 0 {
            return Err(format!(
                "{}: owned by uid {}, not root",
                step.display(),
                meta.uid()
            ));
        }
        if meta.mode() & 0o022 != 0 && !(meta.is_dir() && meta.mode() & 0o1000 != 0) {
            return Err(format!(
                "{}: writable by group or others (mode {:o})",
                step.display(),
                meta.mode() & 0o7777
            ));
        }
        current = step.parent();
    }
    Ok(())
}

/// The machine's own network namespace, as process 1's `/proc` link names
/// it (`net:[<inode>]`); empty when it cannot be read.
#[must_use]
pub fn host_network_namespace() -> String {
    std::fs::read_link("/proc/1/ns/net")
        .map(|link| link.display().to_string())
        .unwrap_or_default()
}

/// The account `name`: its uid, gid and home directory.
///
/// # Errors
///
/// No such account, or the lookup failed.
pub fn account(name: &str) -> io::Result<(u32, u32, std::path::PathBuf)> {
    let c =
        CString::new(name).map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut buffer = vec![0_u8; 16 * 1024];
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the call; the buffer outlives the
    // entry's strings, which are copied out before it is dropped.
    let answer = unsafe {
        libc::getpwnam_r(
            c.as_ptr(),
            entry.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &raw mut found,
        )
    };
    if answer != 0 {
        return Err(io::Error::from_raw_os_error(answer));
    }
    if found.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no account named {name}"),
        ));
    }
    // SAFETY: getpwnam_r found the entry and filled it.
    let entry = unsafe { entry.assume_init() };
    // SAFETY: pw_dir points into `buffer`, NUL terminated.
    let home = unsafe { std::ffi::CStr::from_ptr(entry.pw_dir) };
    Ok((
        entry.pw_uid,
        entry.pw_gid,
        std::path::PathBuf::from(OsStr::from_bytes(home.to_bytes())),
    ))
}

/// The boot clock in nanoseconds (`CLOCK_BOOTTIME`).
#[must_use]
pub fn boot_ns() -> u64 {
    use crate::gpu_execution_node::jobs::NodeClock as _;
    crate::gpu_execution_node::jobs::SystemNodeClock.boot_ns()
}

/// The kernel's id of this boot.
#[must_use]
pub fn boot_id() -> String {
    use crate::gpu_execution_node::jobs::NodeClock as _;
    crate::gpu_execution_node::jobs::SystemNodeClock.boot_id()
}
