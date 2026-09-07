use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File, Permissions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
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
    /// Linux uses a pinned fd path; other Unix platforms fail closed.
    pub fn bind(runtime_dir: &Path, socket_name: &OsStr) -> io::Result<Self> {
        validate_name(socket_name)?;
        let directory = open_directory(runtime_dir)?;
        let address = descriptor_path(&directory, socket_name)?;
        match fs::symlink_metadata(&address) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "socket path occupied",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        // bind does not replace an entry that appears after the existence check.
        // Owner-only runtime permissions protect the socket before chmod.
        let listener = UnixListener::bind(&address)?;
        let metadata = fs::symlink_metadata(&address)?;
        if !metadata.file_type().is_socket() {
            return Err(io::Error::other("socket identity changed"));
        }
        let guard = Self {
            listener: Some(listener),
            directory,
            name: socket_name.to_owned(),
            path: runtime_dir.join(socket_name),
            identity: Some((metadata.dev(), metadata.ino())),
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
        let address = descriptor_path(&self.directory, &self.name)?;
        match fs::symlink_metadata(&address) {
            Ok(metadata)
                if metadata.file_type().is_socket()
                    && (metadata.dev(), metadata.ino()) == identity =>
            {
                fs::remove_file(address)
            }
            // A foreign replacement is not ours to remove, including symlinks.
            Ok(_) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
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

fn descriptor_path(directory: &File, name: &OsStr) -> io::Result<PathBuf> {
    if !cfg!(target_os = "linux") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "descriptor-relative socket binding requires Linux",
        ));
    }
    Ok(PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd())).join(name))
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
