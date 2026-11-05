//! The inherited manager-created listener is the native transport authority.
//! Its filesystem path stays inside the manager's 0700 directory: the tenant
//! cannot stat that path, and inheriting a socket fd does not grant traversal.

use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

/// One genuinely inherited HOST listener, consumed once by managed startup.
/// This owns the socket; there is no public raw-identity/proof constructor.
pub struct HostLegalChannel {
    listener: tokio::net::UnixListener,
    host_uid: u32,
}

/// A connection accepted ONLY by the admitted listener. It has no public
/// fields or constructor; neither a request nor an owner credential makes one.
pub struct HostLegalConnection {
    pub(super) stream: UnixStream,
    /// Set once this connection carries a prospective order.
    pub(super) prospective: Arc<AtomicBool>,
}

impl HostLegalChannel {
    /// Validate the actual inherited AF_UNIX listening socket before adoption.
    /// LC's launcher owns binding/private-path permissions BEFORE uid drop;
    /// fd ownership remains the manager's and is read here with fstat.
    pub fn from_listener(listener: UnixListener, host_uid: u32) -> io::Result<Self> {
        // SAFETY: geteuid has no pointer or ownership preconditions.
        if host_uid == unsafe { libc::geteuid() } {
            return Err(denied());
        }
        if listener.local_addr()?.as_pathname().is_none() {
            return Err(denied());
        }
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: borrowed live fd and a correctly sized writable stat output.
        if unsafe { libc::fstat(listener.as_raw_fd(), metadata.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful fstat initialized the complete stat output.
        let metadata = unsafe { metadata.assume_init() };
        if metadata.st_uid != host_uid || metadata.st_mode & libc::S_IFMT != libc::S_IFSOCK {
            return Err(denied());
        }
        let mut accepting: libc::c_int = 0;
        let mut len = std::mem::size_of_val(&accepting) as libc::socklen_t;
        // SAFETY: output and length match SO_ACCEPTCONN; socket stays borrowed.
        let rc = unsafe {
            libc::getsockopt(
                listener.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ACCEPTCONN,
                (&mut accepting as *mut libc::c_int).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        if len as usize != std::mem::size_of_val(&accepting) || accepting != 1 {
            return Err(denied());
        }
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener: tokio::net::UnixListener::from_std(listener)?,
            host_uid,
        })
    }

    /// Only the kernel UID of this SAME accepted connection admits a HOST.
    pub async fn accept(&self) -> io::Result<HostLegalConnection> {
        let (stream, _) = self.listener.accept().await?;
        if stream.peer_cred()?.uid() != self.host_uid {
            return Err(denied());
        }
        Ok(HostLegalConnection {
            stream: stream.into_std()?,
            prospective: Arc::default(),
        })
    }
}

impl HostLegalConnection {
    /// Shutdown-only ownership for managed teardown. It is an accepted stream,
    /// not a cloned listener or authority that admits another connection.
    pub fn shutdown_handle(&self) -> io::Result<UnixStream> {
        self.stream.try_clone()
    }

    /// True once this connection carries a prospective order. Managed
    /// teardown shuts every other accepted stream at its stop trigger and
    /// leaves this one open for the final drain
    /// ([`crate::Vault::finish_host_legal_prospective`]).
    pub fn prospective_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.prospective)
    }
}

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "HOST legal channel identity",
    )
}
