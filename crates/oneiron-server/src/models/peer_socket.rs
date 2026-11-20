//! A Unix socket connection to a worker this server supervises, checked
//! before any byte of a request leaves (I2-LOCAL): the process that answers
//! runs as this process's own user, and, for a launch on Linux or macOS, it
//! is that launch's supervised child. The EXL3 native channel and the HTTP
//! exchanges with a llama.cpp worker on its own socket (`listen = "unix"`,
//! L9-15) both connect here, so one proof stands for both.
use std::io;
use std::path::Path;

use tokio::net::UnixStream;

/// Connects to the socket at `path`; refused unless the process that
/// answers runs as this process's own user. The peer's pid comes back where
/// this platform names it (Linux and macOS), else `None`.
pub(in crate::models) async fn connect_own_user(
    path: &Path,
) -> io::Result<(UnixStream, Option<u32>)> {
    let stream = UnixStream::connect(path).await?;
    let peer = stream.peer_cred()?;
    if peer.uid() != rustix::process::geteuid().as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the worker's socket answers as another user",
        ));
    }
    let pid = peer.pid().and_then(|pid| u32::try_from(pid).ok());
    Ok((stream, pid))
}

/// Connects to `launch`'s socket; refused unless the process that answers
/// runs as this process's own user and is the launch's supervised child.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(in crate::models) async fn connect_launch(
    launch: &super::worker_host::SocketLaunch,
) -> io::Result<UnixStream> {
    let (stream, pid) = connect_own_user(launch.socket()).await?;
    if !launch.peer_matches(pid) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the socket's peer is not this launch's supervised child",
        ));
    }
    Ok(stream)
}
