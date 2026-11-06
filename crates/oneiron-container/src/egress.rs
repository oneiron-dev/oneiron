//! Host-owned transport. Implemented by the engine, never by guest code.

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::AtomicBool;

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
    #[serde(
        serialize_with = "serialize_response_body",
        deserialize_with = "deserialize_response_body"
    )]
    pub body: bytes::Bytes,
}

fn serialize_response_body<S: serde::Serializer>(
    body: &bytes::Bytes,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serde::Serialize::serialize(body.as_ref(), serializer)
}

fn deserialize_response_body<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<bytes::Bytes, D::Error> {
    <Vec<u8> as serde::Deserialize<'de>>::deserialize(deserializer).map(Into::into)
}

/// The same engine proxy serves native sockets, DNS and browser HTTP reads.
/// Address checks and policy receipts belong to that proxy, outside the fence.
pub trait EgressRelay: Send + Sync + 'static {
    fn connect(&self, target: SocketAddr) -> io::Result<TcpStream>;
    /// Connects a guest stream to `target` as [`EgressRelay::connect`]
    /// does, and says whether a name gates its upload: `true` sends the
    /// guest's opening bytes through [`EgressRelay::open_upload`] before any
    /// of them reaches the remote (FIX 7652). The default gates nothing.
    fn connect_stream(&self, target: SocketAddr) -> io::Result<(TcpStream, bool)> {
        self.connect(target).map(|stream| (stream, false))
    }
    /// Reads a gated stream's opening bytes from `guest` while `alive`
    /// holds, until the name they carry to `target` is judged, and answers
    /// the bytes to send first; every later byte goes on unread. An error
    /// refuses the stream: nothing the guest wrote reaches the remote. Read
    /// after the guest was told its connect succeeded. The default reads
    /// nothing.
    fn open_upload(
        &self,
        _target: SocketAddr,
        _guest: &mut dyn io::Read,
        _alive: &AtomicBool,
    ) -> io::Result<Vec<u8>> {
        Ok(Vec::new())
    }
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
    /// Records one credential forwarding/resolution decision as metadata
    /// only. A relay that keeps no receipts records nothing; a record that
    /// fails never changes what the guest is answered.
    fn record_credential(&self, _record: &CredentialEgressRecord) -> io::Result<()> {
        Ok(())
    }
}

/// One credential forwarding/resolution decision, as metadata only.
///
/// Plain owned descriptor: the actual VM id, the opaque handle ref, the
/// actual operation/effect when known, the normalized destination
/// scheme/bare host when known, the outcome status, and the material byte
/// count on success only. No raw args, credential material, resolver or
/// transport error text, HTTP body, final URL, or content hash claim.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CredentialEgressRecord {
    pub vm_id: String,
    pub handle_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effect: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    pub status: CredentialEgressStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub material_bytes: Option<usize>,
}

/// How one credential forwarding/resolution decision ended.
///
/// `Forwarded` means the transport read returned `Ok`; `Resolved` means
/// inject only resolved, measured and scrubbed, never a transport
/// injection or HTTP response.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialEgressStatus {
    Forwarded,
    Resolved,
    InvalidDestination,
    Unarmed,
    AllowlistDenied,
    ResolverFailed,
    EmptyMaterial,
    TransportFailed,
    TransportUnavailable,
}

impl CredentialEgressStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Forwarded => "forwarded",
            Self::Resolved => "resolved",
            Self::InvalidDestination => "invalid_destination",
            Self::Unarmed => "unarmed",
            Self::AllowlistDenied => "allowlist_denied",
            Self::ResolverFailed => "resolver_failed",
            Self::EmptyMaterial => "empty_material",
            Self::TransportFailed => "transport_failed",
            Self::TransportUnavailable => "transport_unavailable",
        }
    }
}

/// A guest call the fence refused because only the guest's own loopback
/// (127.0.0.0/8, its IPv4-mapped form, and ::1) holds listeners, inside its
/// own session. The guest is answered an errno; the host records this.
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
    /// Neither 127.0.0.0/8 (an IPv4-mapped form included) nor ::1.
    NotLoopback,
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
            Self::Datagram => "datagram",
            Self::NotListening => "not_listening",
            Self::NoListener => "no_listener",
        }
    }
}
