//! Host-owned transport. Implemented by the engine, never by guest code.

use std::io;
use std::net::{SocketAddr, TcpStream};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct HttpRequest {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub follow_redirects: bool,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct HttpResponse {
    pub url: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// The same engine proxy serves native sockets, DNS and browser HTTP reads.
/// Address checks and policy receipts belong to that proxy, outside the fence.
pub trait EgressRelay: Send + Sync + 'static {
    fn connect(&self, target: SocketAddr) -> io::Result<TcpStream>;
    fn authorize_datagram(&self, target: SocketAddr) -> io::Result<()>;
    fn record_session(&self, manifest: &crate::SessionManifest) -> io::Result<()>;
    fn record_abandoned(&self, manifest: &crate::SessionManifest) -> io::Result<()>;
    fn datagram(&self, target: SocketAddr, bytes: &[u8]) -> io::Result<Vec<u8>>;
    fn fetch(&self, request: HttpRequest) -> io::Result<HttpResponse>;
    fn transferred(&self, target: SocketAddr, content_hash: [u8; 32], bytes: u64);
    /// The host floor this relay's guest network work is charged to: each
    /// socket's entry and writer, and each relayed datagram (FIX 5978,
    /// FIX 5979). A relay names its floor; none defaults to charging nothing.
    fn host_net_floor(&self) -> &dyn crate::HostNetFloor;
    /// Records a loopback call the fence refused, as a blocked receipt that
    /// names its address. A relay that keeps no receipts records nothing; a
    /// record that fails never changes what the guest is answered.
    fn record_refusal(&self, _refusal: &LoopbackRefusal) -> io::Result<()> {
        Ok(())
    }
}

/// A guest call the fence refused because only the guest's own loopback
/// (127.0.0.0/8 and ::1) holds listeners, inside its own session. The guest
/// is answered an errno; the host records this.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LoopbackRefusal {
    pub operation: LoopbackOperation,
    /// The address the call named, or the one it would have taken.
    pub address: SocketAddr,
    pub reason: LoopbackRefusalReason,
}

/// The guest call a [`LoopbackRefusal`] answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoopbackOperation {
    Bind,
    Listen,
    Accept,
    Connect,
}

impl LoopbackOperation {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bind => "bind",
            Self::Listen => "listen",
            Self::Accept => "accept",
            Self::Connect => "connect",
        }
    }
}

/// Why the fence refused a loopback call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoopbackRefusalReason {
    /// The unspecified address (0.0.0.0, ::), or a listen with no bind
    /// before it, which would take it.
    Wildcard,
    /// Neither 127.0.0.0/8 nor ::1.
    NotLoopback,
    /// An IPv4-mapped IPv6 address (::ffff:a.b.c.d).
    MappedAddress,
    /// A datagram socket: the fence keeps stream listeners only.
    Datagram,
    /// An accept on a socket that is not listening.
    NotListening,
    /// A loopback connect that no listener of this session holds.
    NoListener,
}

impl LoopbackRefusalReason {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wildcard => "wildcard",
            Self::NotLoopback => "not_loopback",
            Self::MappedAddress => "mapped_address",
            Self::Datagram => "datagram",
            Self::NotListening => "not_listening",
            Self::NoListener => "no_listener",
        }
    }
}
