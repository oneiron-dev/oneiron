//! A render's relay (FIX 7333): every connection and datagram the guest's
//! sockets reach for off the guest's own session crosses here, a page
//! WebSocket's and a worker's included, which no request interception sees.
//! On a managed node each one is checked by the address it goes to, with the
//! render's guard, right before the host connects or sends to that exact
//! address, a reconnect's included; a refused one is kept for the render and
//! fails with the typed hosted-infrastructure refusal. Nothing else is
//! refused, and no name is resolved again.
//!
//! The guest's DNS (port 53, either transport) is answered by the host's own
//! resolvers, as `/etc/resolv.conf` names them, whatever server the guest
//! named: those are the host's, no page's destination, and are not checked,
//! and their answers go back as given. Each address a page then connects to
//! is checked at its connect. The relay keeps no receipts, as a render
//! serves no run, and charges the guest's network work to the floor the
//! vault's host lent.

use std::io::{self, Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use oneiron::Vault;
use oneiron::web_fetch::HostedInfrastructureRefusal;
use oneiron_container::{
    EgressRelay, HostNetFloor, HostNetPermit, HttpRequest, HttpResponse, SessionManifest,
};

use super::Operation;
use super::handler::{PageRequests, Unanswered};

/// The port a guest's DNS goes to.
const DNS_PORT: u16 = 53;
/// The largest datagram a relayed answer carries.
const DATAGRAM_BYTES: usize = 65536;

/// The relay of one render's guest.
pub(super) struct HeadlessRelay {
    operation: Arc<Operation>,
    /// Performs an HTTP request the guest's browser hands the relay.
    requests: Arc<PageRequests>,
    vault: Arc<Vault>,
    /// The bound on each blocking read of a relayed datagram's answer and of
    /// a DNS answer: the browser's own wait cap.
    wait_cap: Duration,
}

impl HeadlessRelay {
    pub(super) fn new(
        operation: Arc<Operation>,
        requests: Arc<PageRequests>,
        vault: Arc<Vault>,
        wait_cap: Duration,
    ) -> Self {
        Self {
            operation,
            requests,
            vault,
            wait_cap,
        }
    }

    /// Admits the guest's `scheme` connection or datagram to `target` when
    /// the render's guard admits its address. A refusal is kept for the
    /// render first. Nothing is admitted once the render ended.
    fn admit(&self, scheme: &str, target: SocketAddr) -> io::Result<()> {
        let Some(_running) = self.operation.begin() else {
            return Err(ended());
        };
        self.operation
            .check(&format!("{scheme}://{target}"), target.ip())
            .map_err(|_| refused())
    }
}

/// Charged to the floor the vault's host lent, looked up at each charge
/// ([`Vault::acquire_host_net_floor`]), as a run's relay is charged.
impl HostNetFloor for HeadlessRelay {
    fn acquire(&self, fds: usize, workers: usize) -> io::Result<HostNetPermit> {
        self.vault.acquire_host_net_floor(fds, workers)
    }
}

impl EgressRelay for HeadlessRelay {
    /// To `target` exactly, once the render's guard admits it.
    fn connect(&self, target: SocketAddr) -> io::Result<TcpStream> {
        self.admit("tcp", target)?;
        TcpStream::connect(target)
    }

    /// A datagram socket's destination, checked as its datagrams are; one
    /// for DNS is answered by the host's resolvers.
    fn authorize_datagram(&self, target: SocketAddr) -> io::Result<()> {
        if target.port() == DNS_PORT {
            return Ok(());
        }
        self.admit("udp", target)
    }

    /// A render serves no run: its guest's manifest lands no run receipt.
    fn record_session(&self, _manifest: &SessionManifest) -> io::Result<()> {
        Ok(())
    }

    /// A render serves no run; its session's own lease answers the render
    /// for a guest that was abandoned.
    fn record_abandoned(&self, _manifest: &SessionManifest) -> io::Result<()> {
        Ok(())
    }

    /// Sent to `target` exactly once the render's guard admits it, and its
    /// one answer read; DNS is answered by the host's resolvers.
    fn datagram(&self, target: SocketAddr, bytes: &[u8]) -> io::Result<Vec<u8>> {
        if target.port() == DNS_PORT {
            if self.operation.ended() {
                return Err(ended());
            }
            return resolve(bytes, self.wait_cap);
        }
        self.admit("udp", target)?;
        let socket = UdpSocket::bind(unspecified(target))?;
        socket.set_read_timeout(Some(self.wait_cap))?;
        socket.connect(target)?;
        socket.send(bytes)?;
        let mut answer = vec![0; DATAGRAM_BYTES];
        let read = socket.recv(&mut answer)?;
        answer.truncate(read);
        Ok(answer)
    }

    /// Performed as the render's handler performs a request. A guarded
    /// render's pages take its handler instead, so only an unguarded
    /// render's come here.
    fn fetch(&self, request: HttpRequest) -> io::Result<HttpResponse> {
        self.requests
            .perform(request)
            .map_err(|unanswered| match unanswered {
                Unanswered::Refused => refused(),
                Unanswered::Failed(detail) => io::Error::other(detail),
            })
    }

    /// A render serves no run, so a stream's bytes go to the host's log, not
    /// to a receipt.
    fn transferred(&self, target: SocketAddr, _content_hash: [u8; 32], bytes: u64) {
        tracing::debug!(%target, bytes, "a headless render's guest stream ended");
    }

    fn host_net_floor(&self) -> &dyn HostNetFloor {
        self
    }
}

/// The error a connection or datagram the render's guard refused fails
/// with, carrying the engine's typed refusal.
fn refused() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, HostedInfrastructureRefusal)
}

/// The error the guest's network work fails with once its render ended.
fn ended() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "the render has ended")
}

/// The unspecified local address of `target`'s family, to send from.
fn unspecified(target: SocketAddr) -> SocketAddr {
    let ip = if target.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };
    SocketAddr::new(ip, 0)
}

/// Answers the guest's DNS `query` from the host's resolvers, the first
/// that answers: over UDP, and again over TCP where its answer came back
/// truncated, each read bounded by `wait`.
fn resolve(query: &[u8], wait: Duration) -> io::Result<Vec<u8>> {
    if query.len() < 12 || query[2] & 0x80 != 0 {
        return Err(io::Error::other("DNS query expected"));
    }
    let config = std::fs::read_to_string("/etc/resolv.conf")?;
    let resolvers = config.lines().filter_map(|line| {
        let mut fields = line.split_whitespace();
        (fields.next() == Some("nameserver"))
            .then(|| fields.next()?.parse::<IpAddr>().ok())
            .flatten()
    });
    let mut error = io::Error::other("host has no DNS resolver");
    for resolver in resolvers {
        let resolver = SocketAddr::new(resolver, DNS_PORT);
        match ask_udp(resolver, query, wait) {
            Ok(answer) if answer[2] & 0x02 != 0 => return ask_tcp(resolver, query, wait),
            Ok(answer) => return Ok(answer),
            Err(failed) => error = failed,
        }
    }
    Err(error)
}

fn ask_udp(resolver: SocketAddr, query: &[u8], wait: Duration) -> io::Result<Vec<u8>> {
    let socket = UdpSocket::bind(unspecified(resolver))?;
    socket.set_read_timeout(Some(wait))?;
    socket.connect(resolver)?;
    socket.send(query)?;
    let mut answer = vec![0; DATAGRAM_BYTES];
    let read = socket.recv(&mut answer)?;
    answer.truncate(read);
    answer_to(query, answer)
}

fn ask_tcp(resolver: SocketAddr, query: &[u8], wait: Duration) -> io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect_timeout(&resolver, wait)?;
    stream.set_read_timeout(Some(wait))?;
    stream.set_write_timeout(Some(wait))?;
    let length = u16::try_from(query.len()).map_err(io::Error::other)?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(query)?;
    let mut length = [0; 2];
    stream.read_exact(&mut length)?;
    let mut answer = vec![0; usize::from(u16::from_be_bytes(length))];
    stream.read_exact(&mut answer)?;
    answer_to(query, answer)
}

/// `answer`, where it answers `query`: its id, with the answer bit set.
fn answer_to(query: &[u8], answer: Vec<u8>) -> io::Result<Vec<u8>> {
    if answer.len() < 12 || answer[..2] != query[..2] || answer[2] & 0x80 == 0 {
        return Err(io::Error::other("invalid host DNS reply"));
    }
    Ok(answer)
}
