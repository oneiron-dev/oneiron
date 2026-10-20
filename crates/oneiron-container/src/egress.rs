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
}
