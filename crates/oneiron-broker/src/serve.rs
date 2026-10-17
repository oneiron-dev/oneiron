//! The broker's side of the socket: one call per connection, from the daemon's
//! uid only. The same-user child takes each connection from its parent over
//! the channel it inherited instead ([`serve_channel`]).

use std::io::{self, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustix::io::Errno;
use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, recvmsg};
use tokio::io::Interest;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

use crate::frame::{read_call, write_reply};
use crate::send::{SendPolicy, Sender};
use crate::{Outcome, PROTOCOL_VERSION, ReplyHeader};

/// Calls in flight at once; the next connection waits for a slot.
const MAX_CONCURRENT: usize = 64;

/// How long a peer has to deliver its frame, and to take the reply.
const FRAME_DEADLINE: Duration = Duration::from_secs(10);

/// How long a connect to a socket already at the path may take before the
/// listener behind it counts as live.
const LIVENESS_PROBE: Duration = Duration::from_secs(1);

/// The line a same-user child writes to its stdout, a pipe only its parent
/// holds, once it serves its channel. The parent waits for it.
pub const LISTENING: &[u8] = b"listening\n";

/// A broker serving one daemon.
#[derive(Debug, Clone)]
pub struct ServeConfig {
    /// The Unix socket to listen on, open to every local user (0666). The
    /// fence is the peer-uid check, made on both ends, and the key coming
    /// with each call's frame, never held between calls. The directory the
    /// host provisions is defence in depth.
    pub socket: PathBuf,
    /// The daemon's uid, the only peer served.
    pub client_uid: u32,
    /// How calls are sent.
    pub policy: SendPolicy,
}

/// Listens on the socket and serves calls until the listener fails. A socket
/// file left at the path by an earlier run, with no listener behind it, is
/// replaced; a live one, or any other file there, is an error.
///
/// A broker holds an exclusive lock on `<socket>.lock` from before it looks
/// at the path until it stops, so a second broker on the same path is
/// refused before it can replace a socket the first has just bound.
pub async fn serve(config: ServeConfig) -> io::Result<()> {
    let sender = Arc::new(Sender::new(&config.policy).map_err(io::Error::other)?);
    let mut lock_path = config.socket.clone().into_os_string();
    lock_path.push(".lock");
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(&lock_path)?;
    // Held until serve returns.
    match lock.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => return Err(io::ErrorKind::AddrInUse.into()),
        Err(std::fs::TryLockError::Error(error)) => return Err(error),
    }
    match std::fs::symlink_metadata(&config.socket) {
        Ok(meta) if meta.file_type().is_socket() => {
            // Without blocking: a listener whose queue is full is live too.
            let probe = tokio::time::timeout(LIVENESS_PROBE, UnixStream::connect(&config.socket));
            match probe.await {
                Ok(Err(error)) if error.kind() == io::ErrorKind::ConnectionRefused => {
                    std::fs::remove_file(&config.socket)?;
                }
                Ok(Err(error)) if error.kind() != io::ErrorKind::WouldBlock => return Err(error),
                Ok(_) | Err(_) => return Err(io::ErrorKind::AddrInUse.into()),
            }
        }
        Ok(_) => return Err(io::ErrorKind::AlreadyExists.into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let listener = UnixListener::bind(&config.socket)?;
    // Any local user may connect; only the daemon's uid is answered.
    std::fs::set_permissions(&config.socket, std::fs::Permissions::from_mode(0o666))?;
    let permits = Arc::new(Semaphore::new(MAX_CONCURRENT));
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(_) => {
                // Out of descriptors or an aborted handshake: back off, keep
                // serving.
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        // The kernel names the peer. Anyone but the daemon is closed on before
        // a byte is read.
        if stream.peer_cred().ok().map(|cred| cred.uid()) != Some(config.client_uid) {
            continue;
        }
        let permit = Arc::clone(&permits)
            .acquire_owned()
            .await
            .map_err(io::Error::other)?;
        let sender = Arc::clone(&sender);
        tokio::spawn(async move {
            handle(stream, &sender).await;
            drop(permit);
        });
    }
}

/// Serves the daemon that started this process as its same-user child
/// (`#broker-same-user-open`), over `channel`, the end of a socket pair the
/// daemon made and the child inherited. Each call comes on a socket of its
/// own, whose descriptor the daemon passes over the channel, so the child
/// binds no path and listens on nothing, and no other process can reach it.
/// It writes [`LISTENING`] to its stdout once it serves, and returns when the
/// daemon closes its end.
pub(crate) async fn serve_channel(
    channel: std::os::unix::net::UnixStream,
    policy: &SendPolicy,
) -> io::Result<()> {
    let sender = Arc::new(Sender::new(policy).map_err(io::Error::other)?);
    channel.set_nonblocking(true)?;
    let channel = UnixStream::from_std(channel)?;
    {
        use std::io::Write as _;
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(LISTENING)?;
        stdout.flush()?;
    }
    let permits = Arc::new(Semaphore::new(MAX_CONCURRENT));
    loop {
        channel.readable().await?;
        let fds = match channel.try_io(Interest::READABLE, || receive(&channel)) {
            Ok(Some(fds)) => fds,
            Ok(None) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error),
        };
        // A message with no socket, or more than one, passes nothing.
        let Ok([fd]) = <[OwnedFd; 1]>::try_from(fds) else {
            continue;
        };
        let stream = std::os::unix::net::UnixStream::from(fd);
        let Ok(stream) = stream
            .set_nonblocking(true)
            .and_then(|()| UnixStream::from_std(stream))
        else {
            continue;
        };
        // Taken at once, so the channel never fills while calls wait for a
        // slot.
        let permits = Arc::clone(&permits);
        let sender = Arc::clone(&sender);
        tokio::spawn(async move {
            let Ok(_permit) = permits.acquire_owned().await else {
                return;
            };
            handle(stream, &sender).await;
        });
    }
}

/// The descriptors that came with the channel's next byte, or `None` once
/// the daemon has closed its end. A message whose descriptors did not all
/// fit passes none. The child starts no process, so they need no
/// close-on-exec.
fn receive(channel: &UnixStream) -> io::Result<Option<Vec<OwnedFd>>> {
    let mut byte = [0; 1];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let received = loop {
        let mut iov = [IoSliceMut::new(&mut byte)];
        match recvmsg(channel, &mut iov, &mut control, RecvFlags::empty()) {
            Err(Errno::INTR) => {}
            received => break received?,
        }
    };
    if received.bytes == 0 {
        return Ok(None);
    }
    let mut fds = Vec::new();
    for message in control.drain() {
        if let RecvAncillaryMessage::ScmRights(passed) = message {
            fds.extend(passed);
        }
    }
    if received.flags.contains(ReturnFlags::CTRUNC) {
        // Closed here.
        fds.clear();
    }
    Ok(Some(fds))
}

/// Serves one call. A frame that cannot be read gets no reply: the daemon
/// counts the call as lost.
async fn handle(mut stream: UnixStream, sender: &Sender) {
    let Ok(Ok(call)) = tokio::time::timeout(FRAME_DEADLINE, read_call(&mut stream)).await else {
        return;
    };
    if call.header.shape.streams() {
        // The reply is checked as it streams, so the key is wiped only after
        // its last chunk.
        let checked = call.header.check(&call.body);
        sender
            .stream(
                &call.header,
                checked,
                &call.body,
                &call.secret,
                &mut stream,
                FRAME_DEADLINE,
            )
            .await;
        return;
    }
    let (outcome, body) = match call.header.check(&call.body) {
        Ok(url) => {
            sender
                .send(&call.header, url, &call.body, &call.secret)
                .await
        }
        Err(reason) => (Outcome::Refused { reason }, Zeroizing::new(Vec::new())),
    };
    // The key is wiped here, before the reply is written.
    let call_id = call.header.call;
    let digest = call.header.digest;
    drop(call.secret);
    let reply = ReplyHeader {
        version: PROTOCOL_VERSION,
        call: call_id,
        digest,
        outcome,
    };
    let _ = tokio::time::timeout(FRAME_DEADLINE, write_reply(&mut stream, &reply, &body)).await;
}

#[cfg(all(test, feature = "test-support"))]
mod tests;
