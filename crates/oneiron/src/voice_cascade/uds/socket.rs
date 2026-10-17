use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File, Permissions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Component, Path, PathBuf};

use super::{Connection, Shutdown};

/// Owns one private socket and its pinned runtime-directory descriptor.
/// Never removes a preexisting entry. Drop stops accepted connections and
/// removes only an entry that still has the created socket's device/inode.
/// The host must not mutate this owner-only directory while the guard lives.
pub struct SocketGuard {
    listener: Option<UnixListener>,
    directory: File,
    name: OsString,
    path: PathBuf,
    identity: Option<(u64, u64)>,
    shutdown: Shutdown,
}

impl SocketGuard {
    /// `runtime_dir` must be an absolute, existing, active vault runtime
    /// directory, owned by the effective uid with no group/other access.
    /// `socket_name` must be a single filename of at most 48 bytes.
    /// Refuses all symlink components, traversal and preexisting entries.
    /// Linux binds through a pinned fd path. macOS binds by pathname, checked
    /// before and after to still name the pinned directory, and the socket
    /// to have landed in it; the owner-only directory's own uid could still
    /// race a rename between the checks. Other Unix platforms fail closed.
    pub fn bind(runtime_dir: &Path, socket_name: &OsStr) -> io::Result<Self> {
        validate_name(socket_name)?;
        let directory = open_directory(runtime_dir)?;
        let address = bind_address(&directory, runtime_dir, socket_name)?;
        if entry_at(&directory, socket_name)?.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "socket path occupied",
            ));
        }
        // bind does not replace an entry that appears after the existence check.
        // Owner-only runtime permissions protect the socket before chmod.
        let listener = UnixListener::bind(&address)?;
        let Some((true, dev, ino)) = entry_at(&directory, socket_name)? else {
            return Err(io::Error::other("socket identity changed"));
        };
        if !cfg!(target_os = "linux") {
            same_directory(&directory, runtime_dir)?;
            let named = fs::symlink_metadata(&address)?;
            if (named.dev(), named.ino()) != (dev, ino) {
                return Err(io::Error::other("socket identity changed"));
            }
        }
        let guard = Self {
            listener: Some(listener),
            directory,
            name: socket_name.to_owned(),
            path: runtime_dir.join(socket_name),
            identity: Some((dev, ino)),
            shutdown: Shutdown::default(),
        };
        fs::set_permissions(&address, Permissions::from_mode(0o600))?;
        if let Some(listener) = &guard.listener {
            listener.set_nonblocking(true)?;
        }
        Ok(guard)
    }

    /// Discovery path. The host must keep the runtime directory at this name.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The nonblocking listener for an async host's own admission loop. The
    /// guard still owns the socket: keep it until the clone is dropped.
    pub fn try_clone_listener(&self) -> io::Result<UnixListener> {
        self.listener
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "listener stopped"))?
            .try_clone()
    }

    #[must_use]
    pub fn shutdown_signal(&self) -> Shutdown {
        self.shutdown.clone()
    }

    /// Nonblocking admission only. Enrichment and vault work happen in the
    /// returned connection, never under a listener/global voice-loop lock.
    pub fn try_accept(&self) -> io::Result<Option<Connection>> {
        if self.shutdown.is_requested() {
            return Ok(None);
        }
        let Some(listener) = &self.listener else {
            return Ok(None);
        };
        match listener.accept() {
            Ok((stream, _)) => Ok(Some(Connection::from_stream(stream, self.shutdown.clone()))),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Idempotent. Closes admission and signals all accepted workers. The host
    /// joins its workers after their current synchronous host/core call returns.
    pub fn shutdown(&mut self) -> io::Result<()> {
        self.shutdown.request();
        self.listener = None;
        self.remove_owned_socket()
    }

    fn remove_owned_socket(&mut self) -> io::Result<()> {
        // Disarm once, even on failure or replacement. A later call must not
        // match a reused inode after the original socket has been removed.
        let Some(identity) = self.identity.take() else {
            return Ok(());
        };
        match entry_at(&self.directory, &self.name)? {
            Some((true, dev, ino)) if (dev, ino) == identity => unlink_at(&self.directory, &self.name),
            // A foreign replacement is not ours to remove, including symlinks.
            Some(_) | None => Ok(()),
        }
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn validate_name(name: &OsStr) -> io::Result<()> {
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(_)))
        || components.next().is_some()
        || name.as_bytes().len() > 48
        || name.as_bytes().contains(&0)
        || name.as_bytes().contains(&b'/')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid socket name",
        ));
    }
    Ok(())
}

/// Where the socket is bound: the pinned directory's fd path on Linux, its
/// pathname on macOS once that still names the pinned directory.
fn bind_address(directory: &File, runtime_dir: &Path, name: &OsStr) -> io::Result<PathBuf> {
    if cfg!(target_os = "linux") {
        return Ok(PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd())).join(name));
    }
    if !cfg!(target_os = "macos") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "socket binding needs Linux or macOS",
        ));
    }
    same_directory(directory, runtime_dir)?;
    Ok(runtime_dir.join(name))
}

/// `runtime_dir`, unfollowed, is still the pinned directory.
fn same_directory(directory: &File, runtime_dir: &Path) -> io::Result<()> {
    let pinned = directory.metadata()?;
    let named = fs::symlink_metadata(runtime_dir)?;
    if !named.is_dir() || (named.dev(), named.ino()) != (pinned.dev(), pinned.ino()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "runtime directory moved",
        ));
    }
    Ok(())
}

/// The pinned directory's entry `name`, unfollowed: whether it is a socket,
/// and its device and inode.
#[allow(clippy::unnecessary_cast)]
fn entry_at(directory: &File, name: &OsStr) -> io::Result<Option<(bool, u64, u64)>> {
    let name = c_name(name)?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: directory is a live descriptor, name is NUL-terminated, and
    // stat is writable storage for one libc::stat.
    let rc = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        let error = io::Error::last_os_error();
        return match error.kind() {
            io::ErrorKind::NotFound => Ok(None),
            _ => Err(error),
        };
    }
    // SAFETY: fstatat succeeded, so it filled stat.
    let stat = unsafe { stat.assume_init() };
    Ok(Some((
        stat.st_mode & libc::S_IFMT == libc::S_IFSOCK,
        stat.st_dev as u64,
        stat.st_ino as u64,
    )))
}

fn unlink_at(directory: &File, name: &OsStr) -> io::Result<()> {
    let name = c_name(name)?;
    // SAFETY: directory is a live descriptor and name is NUL-terminated.
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn c_name(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid socket name"))
}

fn open_directory(path: &Path) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "absolute runtime directory required",
        ));
    }
    let mut directory = File::open("/")?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => directory = open_child_directory(&directory, name)?,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "runtime traversal rejected",
                ));
            }
        }
    }
    let metadata = directory.metadata()?;
    // SAFETY: geteuid has no pointer arguments or preconditions.
    let uid = unsafe { libc::geteuid() };
    if metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "runtime directory must be private",
        ));
    }
    Ok(directory)
}

fn open_child_directory(parent: &File, name: &OsStr) -> io::Result<File> {
    let name = CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid runtime directory"))?;
    // SAFETY: parent is a live directory descriptor; name is a terminated C
    // string. No creation mode is needed. O_NOFOLLOW rejects every symlink
    // component and O_DIRECTORY rejects non-directories without opening bodies.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful openat returned a new owned descriptor, transferred once.
    Ok(unsafe { File::from_raw_fd(fd) })
}
