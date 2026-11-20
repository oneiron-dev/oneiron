//! The TLS client stack the pack's mail protocols share: IMAP reads and
//! SMTP submission (fix list row 17872). A TCP stream whose host name is
//! resolved, and whose every read and write ends, by a deadline, the
//! platform's trust roots, and a rustls client that verifies the server's
//! name. Each protocol keeps its own exchange and its own refusal words.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use super::rest::refused;
use crate::error::Result;

/// How long one read or write may wait.
pub(super) const IO_TIMEOUT: Duration = Duration::from_secs(60);

/// A TCP stream whose every read and write ends by its deadline: a server
/// that drips bytes, or never ends an exchange, times out with it.
pub(super) struct DeadlineStream {
    pub(super) tcp: TcpStream,
    pub(super) deadline: Instant,
}

impl DeadlineStream {
    fn remaining(&self) -> std::io::Result<Duration> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::Error::from(std::io::ErrorKind::TimedOut));
        }
        Ok(left.min(IO_TIMEOUT))
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.remaining()?;
        self.tcp.set_read_timeout(Some(left))?;
        self.tcp.read(buf)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let left = self.remaining()?;
        self.tcp.set_write_timeout(Some(left))?;
        self.tcp.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.tcp.flush()
    }
}

/// A TLS session over a [`DeadlineStream`].
pub(super) type TlsStream = rustls::StreamOwned<rustls::ClientConnection, DeadlineStream>;

/// The refusal words one protocol gives the stack's failures.
pub(super) struct TlsRefusals {
    /// The platform holds no trust root rustls takes.
    pub(super) no_roots: &'static str,
    /// The TLS client cannot be set up.
    pub(super) setup: &'static str,
    /// The host is no name a certificate can be checked against.
    pub(super) host: &'static str,
    /// The host does not resolve.
    pub(super) unresolved: &'static str,
    /// The host's name did not resolve before the connect deadline.
    pub(super) resolution_timed_out: &'static str,
    /// No address of the host answers.
    pub(super) connect: &'static str,
}

/// The platform's trust roots, as rustls takes them.
fn platform_roots(refusals: &TlsRefusals) -> Result<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    let (added, _) =
        roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    if added == 0 {
        return Err(refused(refusals.no_roots));
    }
    Ok(roots)
}

/// A TLS client for `host`, its certificate checked against the platform's
/// roots and the host's name. The handshake runs on its first read.
pub(super) fn tls_client(host: &str, refusals: &TlsRefusals) -> Result<rustls::ClientConnection> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| refused(refusals.setup))?
        .with_root_certificates(platform_roots(refusals)?)
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|_| refused(refusals.host))?;
    rustls::ClientConnection::new(Arc::new(config), name).map_err(|_| refused(refusals.setup))
}

/// A TCP connection to `host:port`, the first of its addresses that
/// answers, every read and write of it bounded by `deadline`. The name is
/// resolved within `deadline` too ([`resolve_by`]), then each address is
/// tried within what remains of it.
pub(super) fn connect_tcp(
    host: &str,
    port: u16,
    deadline: Instant,
    refusals: &TlsRefusals,
) -> Result<DeadlineStream> {
    let addresses = resolve_by(host, port, deadline, refusals)?;
    let tcp = addresses
        .into_iter()
        .find_map(|address| {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            TcpStream::connect_timeout(&address, left.min(IO_TIMEOUT)).ok()
        })
        .ok_or_else(|| refused(refusals.connect))?;
    Ok(DeadlineStream { tcp, deadline })
}

/// The addresses of `host:port`, resolved before `deadline` (fix list row
/// 17645). The system's lookup cannot be cancelled, so it runs on a thread
/// of its own, and this call waits for its answer only until `deadline`:
/// past it, the call is refused with `resolution_timed_out`, and an answer
/// that comes later is dropped on that thread.
fn resolve_by(
    host: &str,
    port: u16,
    deadline: Instant,
    refusals: &TlsRefusals,
) -> Result<Vec<SocketAddr>> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(refused(refusals.resolution_timed_out));
    }
    let name = host.to_owned();
    let (send, receive) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("mail-resolve".to_owned())
        .spawn(move || {
            let answer = (name.as_str(), port)
                .to_socket_addrs()
                .map(|addresses| addresses.collect::<Vec<_>>());
            // The caller may have stopped waiting; then the answer goes.
            let _ = send.send(answer);
        })
        .map_err(|_| refused(refusals.unresolved))?;
    match receive.recv_timeout(left) {
        Ok(Ok(addresses)) => Ok(addresses),
        Ok(Err(_)) | Err(RecvTimeoutError::Disconnected) => Err(refused(refusals.unresolved)),
        Err(RecvTimeoutError::Timeout) => Err(refused(refusals.resolution_timed_out)),
    }
}
