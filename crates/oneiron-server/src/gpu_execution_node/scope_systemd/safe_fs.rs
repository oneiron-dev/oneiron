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

/// What `fstat` says of an open file, or `fstatat` of an entry
/// ([`facts_beneath`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileFacts {
    pub uid: u32,
    pub gid: u32,
    /// The permission bits, with set-id and sticky bits.
    pub mode: u32,
    pub is_dir: bool,
    pub is_regular: bool,
    /// A symbolic link: only an entry's own facts ([`facts_beneath`]) say so.
    pub is_link: bool,
    pub size: u64,
    /// How many names the file has (hard links).
    pub links: u64,
    /// The file system's device and the file's inode: which file it is.
    pub device: u64,
    pub inode: u64,
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
    Ok(facts_of(&unsafe { stat.assume_init() }))
}

/// `fstatat` of the entry `name` beneath `dir`, never through a link: a
/// link's own facts, the file it names never opened.
///
/// # Errors
///
/// The kernel refused it (`NotFound` when nothing is at `name`).
pub fn facts_beneath(dir: BorrowedFd<'_>, name: &str) -> io::Result<FileFacts> {
    let c = c_name(OsStr::new(name))?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: c is NUL terminated; fstatat fills the whole buffer when it
    // succeeds, and AT_SYMLINK_NOFOLLOW stats a link itself.
    check(unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            c.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    })?;
    // SAFETY: fstatat succeeded.
    Ok(facts_of(&unsafe { stat.assume_init() }))
}

fn facts_of(stat: &libc::stat) -> FileFacts {
    let kind = stat.st_mode & libc::S_IFMT;
    FileFacts {
        uid: stat.st_uid,
        gid: stat.st_gid,
        mode: stat.st_mode & 0o7777,
        is_dir: kind == libc::S_IFDIR,
        is_regular: kind == libc::S_IFREG,
        is_link: kind == libc::S_IFLNK,
        size: u64::try_from(stat.st_size).unwrap_or(0),
        // nlink_t, dev_t and ino_t are no wider than 64 bits on Linux.
        links: stat.st_nlink as u64,
        device: stat.st_dev as u64,
        inode: stat.st_ino as u64,
    }
}

/// The kind of file `found` is, in words.
fn kind_words(found: &FileFacts) -> &'static str {
    if found.is_link {
        "a link"
    } else if found.is_dir {
        "a directory"
    } else if found.is_regular {
        "a regular file"
    } else {
        "a special file"
    }
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
    // The name could be replaced between the make and the open (review r3
    // R3-08): the directory opened must be this process's with no group or
    // other bits, as the one it made is (mode 0700, the umask only narrows),
    // before it is given an owner and a mode.
    let found = facts(borrow(&made))?;
    // SAFETY: geteuid has no failure.
    if found.uid != unsafe { libc::geteuid() } || found.mode & 0o077 != 0 {
        return Err(io::Error::other(format!(
            "{name}: replaced between its make and its open"
        )));
    }
    // SAFETY: made is the directory this call created and opened.
    check(unsafe { libc::fchown(made.as_raw_fd(), owner.0, owner.1) })?;
    // SAFETY: as above.
    check(unsafe { libc::fchmod(made.as_raw_fd(), mode as libc::mode_t) })?;
    Ok(made)
}

/// Gives the file `name` beneath `dir`, which its maker just made there (the
/// gate's socket, made by root), the group `gid` and `mode`; its owner
/// stays.
///
/// # Errors
///
/// A step failed.
pub fn set_group_and_mode_beneath(
    dir: BorrowedFd<'_>,
    name: &str,
    gid: u32,
    mode: u32,
) -> io::Result<()> {
    let c = c_name(OsStr::new(name))?;
    // SAFETY: c is NUL terminated; AT_SYMLINK_NOFOLLOW changes no link
    // target; the owner (uid_t)-1 is left as it is.
    check(unsafe {
        libc::fchownat(
            dir.as_raw_fd(),
            c.as_ptr(),
            libc::uid_t::MAX,
            gid,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    })?;
    // SAFETY: c is NUL terminated. fchmodat follows no link here: the name's
    // maker made it in a directory only it writes.
    check(unsafe { libc::fchmodat(dir.as_raw_fd(), c.as_ptr(), mode as libc::mode_t, 0) })
}

/// The mode of a lock file [`make_lock_beneath`] makes.
const LOCK_FILE_MODE: u32 = 0o600;

/// Whether the entry `name` beneath a directory, as `found` says, is the
/// lock file [`make_lock_beneath`] makes: an empty regular file `owner`
/// owns, mode 0600, with no other name (a hard link), so it is no file of
/// another directory (review r1 of #10541: install's promise is an empty
/// file of mode 0600, and a file with another mode or with content is not
/// the one it made).
fn lock_entry_fits(found: &FileFacts, owner: u32) -> bool {
    found.is_regular
        && found.uid == owner
        && found.links == 1
        && found.mode == LOCK_FILE_MODE
        && found.size == 0
}

/// Why the entry `found` at `name` is no lock file for `owner`, in words.
fn lock_entry_misfit(name: &str, found: &FileFacts, owner: u32) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "{name} is {} of uid {} with {} name(s), mode {:o} and {} byte(s), not an empty regular file of uid {owner} with one name and mode {LOCK_FILE_MODE:o}",
            kind_words(found),
            found.uid,
            found.links,
            found.mode,
            found.size
        ),
    )
}

/// The lock file `name` beneath `dir`, open read-only to hold a lock on it:
/// an empty regular file `owner` owns with one name and mode 0600, made
/// beforehand ([`make_lock_beneath`]). Nothing at `name` is made, removed
/// or replaced here, and an entry that is not such a file (a link, a hard
/// link, a directory, a pipe, another owner's file, another mode, a file
/// with content) is never opened: it is refused, as it is, and the refusal
/// names it (review r2 of #10540, the Engine's extra review).
///
/// # Errors
///
/// Nothing at `name` (`NotFound`), an entry that is not such a file, an
/// entry that changed between its check and its open, or a failed open.
pub fn open_lock_beneath(dir: BorrowedFd<'_>, name: &str, owner: u32) -> io::Result<OwnedFd> {
    let c = c_name(OsStr::new(name))?;
    let before = facts_beneath(dir, name)?;
    if !lock_entry_fits(&before, owner) {
        return Err(lock_entry_misfit(name, &before, owner));
    }
    // SAFETY: c is NUL terminated; O_NOFOLLOW refuses a link, O_NONBLOCK
    // keeps a pipe from holding the open, and nothing is made.
    let fd = owned(unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NOCTTY | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    })?;
    let held = facts(borrow(&fd))?;
    if (held.device, held.inode) != (before.device, before.inode) || !lock_entry_fits(&held, owner)
    {
        return Err(io::Error::other(format!(
            "{name} changed between its check and its open"
        )));
    }
    Ok(fd)
}

/// Makes the lock file `name` beneath `dir` for [`open_lock_beneath`]: an
/// empty regular file of this process's account, mode 0600 whatever the
/// umask, made when nothing is at `name`; with whether this call made it. A
/// fitting file that is there already is kept; anything else at `name`
/// (another mode or content included) is refused, as it is, for its maker
/// to remove.
///
/// # Errors
///
/// An entry that is not such a file, or a failed make.
pub fn make_lock_beneath(dir: BorrowedFd<'_>, name: &str, owner: u32) -> io::Result<bool> {
    let c = c_name(OsStr::new(name))?;
    match facts_beneath(dir, name) {
        Ok(found) if lock_entry_fits(&found, owner) => return Ok(false),
        Ok(found) => return Err(lock_entry_misfit(name, &found, owner)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    // SAFETY: c is NUL terminated; O_EXCL with O_NOFOLLOW makes a new file
    // or fails.
    let made = owned(unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c.as_ptr(),
            libc::O_RDONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            LOCK_FILE_MODE,
        )
    })?;
    // The umask narrows the mode openat gives (umask 0777 makes it 0000):
    // set it on the file made (review r1 of #10541).
    set_mode(borrow(&made), LOCK_FILE_MODE)?;
    let held = facts(borrow(&made))?;
    if !lock_entry_fits(&held, owner) {
        return Err(io::Error::other(format!(
            "{name}: made, but {}",
            lock_entry_misfit(name, &held, owner)
        )));
    }
    Ok(true)
}

/// Sets the mode of the open file `fd`.
///
/// # Errors
///
/// The kernel refused it.
pub fn set_mode(fd: BorrowedFd<'_>, mode: u32) -> io::Result<()> {
    // SAFETY: fd is an open descriptor; fchmod follows no name.
    check(unsafe { libc::fchmod(fd.as_raw_fd(), mode as libc::mode_t) })
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
    require_owned_by_root_or(path, 0)
}

/// [`require_root_owned`], with `owner`'s steps allowed beside root's: for
/// a step root runs, `owner` is root, and a test's own account stands in.
///
/// # Errors
///
/// The first path that is not, and why.
pub fn require_owned_by_root_or(path: &Path, owner: u32) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;
    let mut current = Some(path);
    while let Some(step) = current {
        let meta = std::fs::symlink_metadata(step)
            .map_err(|error| format!("{}: {error}", step.display()))?;
        if meta.file_type().is_symlink() {
            return Err(format!("{}: a link; give the real path", step.display()));
        }
        if meta.uid() != 0 && meta.uid() != owner {
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
    account_entry(name).map(|found| (found.uid, found.gid, found.home))
}

/// The groups of the account `name` whose primary group is `gid`, from the
/// group database (`getgrouplist`): the groups a service run as that account
/// starts with, before a unit's own `SupplementaryGroups=`.
///
/// # Errors
///
/// The lookup failed.
pub fn account_groups(name: &str, gid: u32) -> io::Result<Vec<u32>> {
    let c =
        CString::new(name).map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let mut room: libc::c_int = 32;
    loop {
        let mut groups: Vec<libc::gid_t> = vec![0; usize::try_from(room).unwrap_or(0)];
        let mut found = room;
        // SAFETY: `c` is NUL terminated, and `groups` holds `found` entries.
        let read = unsafe { libc::getgrouplist(c.as_ptr(), gid, groups.as_mut_ptr(), &mut found) };
        if read >= 0 {
            groups.truncate(usize::try_from(found).unwrap_or(0));
            return Ok(groups);
        }
        if found <= room || room >= 65_536 {
            return Err(io::Error::other(format!(
                "the group list of {name} did not read"
            )));
        }
        room = found;
    }
}

/// One account's entry in the account database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountEntry {
    pub uid: u32,
    pub gid: u32,
    pub home: std::path::PathBuf,
    pub shell: std::path::PathBuf,
}

/// The account `name`'s entry.
///
/// # Errors
///
/// No such account (`NotFound`), or the lookup failed.
pub fn account_entry(name: &str) -> io::Result<AccountEntry> {
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
    // SAFETY: pw_dir and pw_shell point into `buffer`, NUL terminated.
    let (home, shell) = unsafe {
        (
            std::ffi::CStr::from_ptr(entry.pw_dir),
            std::ffi::CStr::from_ptr(entry.pw_shell),
        )
    };
    Ok(AccountEntry {
        uid: entry.pw_uid,
        gid: entry.pw_gid,
        home: std::path::PathBuf::from(OsStr::from_bytes(home.to_bytes())),
        shell: std::path::PathBuf::from(OsStr::from_bytes(shell.to_bytes())),
    })
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
