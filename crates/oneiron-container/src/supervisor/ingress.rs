//! The trusted session holder's peer of a guest loopback connection.

use super::{Guard, NativeFenceGuard, State, loopback};
use crate::HostNetPermit;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::os::unix::net::UnixStream;
use std::sync::Weak;

/// One host peer and its descriptor's room on the original host floor.
/// The guest peer enters the same queue as a guest's loopback connect.
pub struct LoopbackConnection {
    stream: UnixStream,
    charge: HostNetPermit,
}

impl LoopbackConnection {
    pub(super) fn new(stream: UnixStream, charge: HostNetPermit) -> Self {
        Self { stream, charge }
    }

    /// Carries an already admitted native transport and its original floor
    /// permit together. This constructor performs no port or authority check.
    pub fn from_parts(stream: UnixStream, charge: HostNetPermit) -> Self {
        Self { stream, charge }
    }

    /// Transfers the stream and its room together. Keep the permit until
    /// the stream closes, including when adapting it to an async runtime.
    pub fn into_parts(self) -> (UnixStream, HostNetPermit) {
        (self.stream, self.charge)
    }
}

impl Read for LoopbackConnection {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.stream.read(bytes)
    }
}

impl Write for LoopbackConnection {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

fn connect(
    state: &Weak<State>,
    target: SocketAddr,
    waiting: impl Fn() -> bool,
) -> io::Result<LoopbackConnection> {
    let state = state
        .upgrade()
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EINTR))?;
    loopback::connect_host(&state, target, waiting)
}

impl Guard {
    pub(crate) fn connect_loopback(
        &self,
        target: SocketAddr,
        waiting: impl Fn() -> bool,
    ) -> io::Result<LoopbackConnection> {
        connect(&self.state, target, waiting)
    }
}

impl NativeFenceGuard {
    /// Opens an independent peer of this fence's exact loopback listener.
    /// A full backlog waits in the ordinary ticket line while `waiting`
    /// holds. This does not open a host or guest kernel INET listener.
    pub fn connect_loopback(
        &self,
        target: SocketAddr,
        waiting: impl Fn() -> bool,
    ) -> io::Result<LoopbackConnection> {
        connect(&self.state, target, waiting)
    }
}

impl crate::GuestSession {
    /// Opens a stream into this fenced session, not another session or the
    /// host network. The caller owns port admission and cancellation.
    pub fn connect_loopback(
        &self,
        target: SocketAddr,
        waiting: impl Fn() -> bool,
    ) -> io::Result<LoopbackConnection> {
        self.supervisor
            .as_ref()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::Unsupported, "session has no native fence")
            })?
            .connect_loopback(target, waiting)
    }
}
