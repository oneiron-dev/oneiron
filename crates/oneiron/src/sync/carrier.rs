//! What a sync socket rides on (OF-535): TCP to the home's URL, or a stream a
//! [`SyncDialer`] opens, such as a paired machine's mesh connection. The HTTP
//! upgrade, its slip and machine proofs, and every WebSocket frame are the
//! same bytes on either; only the carrier under them changes.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::error::{Error as WsError, UrlError};

use crate::sync::transport::{MAX_CODEC_INNER_BYTES, WireSocket};

/// An ordered, reliable byte stream a sync socket can ride on.
pub trait SyncStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> SyncStream for T {}

/// One dial in flight.
pub type SyncDial<'a> = Pin<Box<dyn Future<Output = io::Result<Box<dyn SyncStream>>> + Send + 'a>>;

/// Opens a carrier to the home other than TCP to its URL. The stream it
/// returns must already be private to the machine it names: the upgrade runs
/// on it in the clear.
pub trait SyncDialer: Send + Sync + std::fmt::Debug {
    fn dial(&self) -> SyncDial<'_>;
}

/// FIX 4748: the carriers to this device's other machines while its home is
/// down. A peer has no URL: each dial rides the paired mesh to the machine it
/// names, private to it as a [`SyncDialer`]'s stream is, and the upgrade, its
/// slip and machine proofs are the bytes a home dial carries.
pub trait SyncPeerDialer: Send + Sync + std::fmt::Debug {
    /// The machines this device may sync with while its home is down, the
    /// standby home first ([`crate::sync::peer_route::choose_sync_peer`]);
    /// empty when none may.
    fn peers(&self) -> Vec<crate::EntityId>;
    /// Opens the stream one sync socket to `peer` rides.
    fn dial_peer(&self, peer: crate::EntityId) -> SyncDial<'_>;
}

/// One peer's dial as the [`SyncDialer`] a peer session's socket rides
/// (FIX 4748).
#[derive(Debug)]
pub(crate) struct PeerDial<'a> {
    pub(crate) dialer: &'a dyn SyncPeerDialer,
    pub(crate) peer: crate::EntityId,
}

impl SyncDialer for PeerDial<'_> {
    fn dial(&self) -> SyncDial<'_> {
        self.dialer.dial_peer(self.peer)
    }
}

/// The carrier under one sync socket.
pub enum SyncIo {
    Tcp(TcpStream),
    Dialed(Box<dyn SyncStream>),
}

impl AsyncRead for SyncIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Dialed(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for SyncIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Dialed(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            Self::Dialed(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Dialed(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// A sync WebSocket on either carrier, speaking the codec frame toward our own
/// server (ARCH-0081 §7).
pub(crate) type SyncSocket = WireSocket<WebSocketStream<SyncIo>>;

/// The most bytes one message from the home may reassemble to on a sync
/// socket (ABC transport row T25): a 1024th of this machine's memory, never
/// under 64 MiB, and 64 MiB when memory cannot be read, the derivation of the
/// server's request floor, in place of tungstenite's implicit 64 MiB.
fn sync_socket_message_bytes() -> usize {
    const FLOOR: u64 = 64 * 1024 * 1024;
    let bytes =
        crate::host_memory::memory_bytes().map_or(FLOOR, |memory| (memory / 1024).max(FLOOR));
    usize::try_from(bytes).unwrap_or(usize::MAX)
}

/// The request header a member lane's upgrade carries, valued
/// [`MEMBER_LANE_HEADER_VALUE`]: it asks for the selector-only lane and grants
/// nothing (H8-SHARED-ENV-LANE = B, MEMBER-SYNC D1; shared here so both
/// client upgrade builders send the same bytes the home's member arm reads).
pub const MEMBER_LANE_HEADER: &str = "oneiron-sync-lane";
/// The one value of [`MEMBER_LANE_HEADER`].
pub const MEMBER_LANE_HEADER_VALUE: &str = "member";
/// The response header a refused upgrade carries when the home names why it
/// refused (MEMBER-SYNC-WORLD-PACT = C).
pub const UPGRADE_REFUSAL_HEADER: &str = "oneiron-upgrade-refusal";
/// The one value of [`UPGRADE_REFUSAL_HEADER`]: the lane's grant stands under
/// a world-bounded pact, whose ceiling is narrower than All, and per-world
/// lanes are not built yet, so the lane parks and the member sees why.
pub const UPGRADE_REFUSAL_WORLD_BOUNDED_PACT: &str = "world-bounded-pact";

/// Why the home refused a sync upgrade with 403, when it names one
/// (MEMBER-SYNC-WORLD-PACT = C). A bare 403 carries `None`: the credential is
/// still refused the socket, only the reason is untold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForbiddenReason {
    /// The member lane's grant stands under a world-bounded pact: the home
    /// would serve the lane nothing, so it refuses the lane instead of
    /// running it silently empty, and the client parks through the typed stop.
    WorldBoundedPact,
}

impl ForbiddenReason {
    /// The reason an [`UPGRADE_REFUSAL_HEADER`] `value` names, when it names
    /// one this build knows. Unknown values answer `None`: a newer home's
    /// reason still refuses the socket, only untold.
    pub(crate) fn from_wire(value: &str) -> Option<Self> {
        if value
            .trim()
            .eq_ignore_ascii_case(UPGRADE_REFUSAL_WORLD_BOUNDED_PACT)
        {
            Some(Self::WorldBoundedPact)
        } else {
            None
        }
    }
}

/// The home's HTTP refusal of a sync upgrade, by what it refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpgradeRefusal {
    /// 401: it did not accept the credential the upgrade carried (FIX 12442).
    Unauthorized,
    /// 403: it accepted the credential and refuses that credential this
    /// socket, so a redial on it is refused again (MEMBER-SELECTOR-SOCKET).
    /// It carries the reason the home named, when it named one.
    Forbidden(Option<ForbiddenReason>),
}

impl UpgradeRefusal {
    /// The event the host is told this refusal by.
    pub(crate) fn event(self) -> crate::sync::client::SyncEvent {
        match self {
            Self::Unauthorized => crate::sync::client::SyncEvent::UpgradeUnauthorized,
            Self::Forbidden(reason) => crate::sync::client::SyncEvent::UpgradeForbidden { reason },
        }
    }
}

/// The home's refusal `error` is, when it is the home's HTTP 401 or 403
/// answer to the upgrade; `None` for any other failure. A 403 refuses the
/// credential the upgrade carried, so a 403 to an upgrade that `carried` none
/// (a clear socket off loopback and mesh withholds it, FIX 11111) refuses
/// nothing this machine holds and stays the far end's failure. A 403 that
/// names its reason in [`UPGRADE_REFUSAL_HEADER`] is told with it. The home
/// dial, the residence RPC dial and a peer session's probe of the home read a
/// failed upgrade by this one rule.
pub(crate) fn upgrade_refusal(error: &WsError, carried: bool) -> Option<UpgradeRefusal> {
    use tokio_tungstenite::tungstenite::http::StatusCode;
    let WsError::Http(response) = error else {
        return None;
    };
    match response.status() {
        StatusCode::UNAUTHORIZED => Some(UpgradeRefusal::Unauthorized),
        StatusCode::FORBIDDEN if carried => {
            let reason = response
                .headers()
                .get(UPGRADE_REFUSAL_HEADER)
                .and_then(|value| value.to_str().ok())
                .and_then(ForbiddenReason::from_wire);
            Some(UpgradeRefusal::Forbidden(reason))
        }
        _ => None,
    }
}

/// Whether `error` is this machine's own setup of a sync socket, not the
/// carrier or the far end failing (FIX 22217): a URL this build cannot dial,
/// `wss` with no TLS or one with no host name, which no answer of the far
/// end mends. A URL nobody answered ([`UrlError::UnableToConnect`]) is the
/// far end's. The home session's connect and the residence dial both read
/// a failed [`connect_sync_socket`] by this one rule.
pub(crate) fn own_setup_fault(error: &WsError) -> bool {
    matches!(error, WsError::Url(url) if !matches!(url, UrlError::UnableToConnect(_)))
}

/// Opens `request`'s WebSocket on `dialer`'s carrier when there is one, else on
/// TCP to the request's host. A carrier that fails to dial falls back to TCP
/// when the URL carries credentials by itself (FIX 3374): `wss`, or `ws` to a
/// loopback address, never a clear `ws` to another host, which the request's
/// slip was not signed to cross. TCP carries `ws` only: this build has no TLS,
/// so a `wss` URL is refused as `connect_async` refuses it. Returns the
/// upgrade response's headers beside the socket: the home names itself there.
pub(crate) async fn connect_sync_socket(
    request: impl IntoClientRequest + Unpin,
    dialer: Option<&dyn SyncDialer>,
) -> Result<(SyncSocket, tokio_tungstenite::tungstenite::http::HeaderMap), WsError> {
    let request = request.into_client_request()?;
    let io = open_carrier(request.uri(), dialer).await?;
    let config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
        .max_message_size(Some(sync_socket_message_bytes()));
    let (socket, response) =
        tokio_tungstenite::client_async_with_config(request, io, Some(config)).await?;
    Ok((
        WireSocket::to_our_server(socket, MAX_CODEC_INNER_BYTES),
        response.into_parts().0.headers,
    ))
}

/// The carrier one sync socket to `uri` rides: `dialer`'s stream when there
/// is one, else TCP to the URI's host, `ws` only. A carrier that fails to
/// dial falls back to TCP when the URL carries credentials by itself (FIX
/// 3374).
async fn open_carrier(
    uri: &tokio_tungstenite::tungstenite::http::Uri,
    dialer: Option<&dyn SyncDialer>,
) -> Result<SyncIo, WsError> {
    match dialer {
        Some(dialer) => match dialer.dial().await {
            Ok(stream) => Ok(SyncIo::Dialed(stream)),
            Err(error)
                if crate::sync::client::endpoint::admits_credentials(&uri.to_string(), false) =>
            {
                tracing::debug!(%error, "sync carrier dial failed; dialing the URL");
                // A URL that does not open either leaves the carrier's own
                // failure standing.
                tcp(uri).await.map_err(|_| WsError::Io(error))
            }
            Err(error) => Err(WsError::Io(error)),
        },
        None => tcp(uri).await,
    }
}

/// TCP to `uri`'s host, for `ws`; `wss` is refused.
async fn tcp(uri: &tokio_tungstenite::tungstenite::http::Uri) -> Result<SyncIo, WsError> {
    if uri.scheme_str() == Some("wss") {
        return Err(WsError::Url(UrlError::TlsFeatureNotEnabled));
    }
    let host = uri
        .host()
        .ok_or(WsError::Url(UrlError::NoHostName))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let port = uri.port_u16().unwrap_or(80);
    Ok(SyncIo::Tcp(
        TcpStream::connect((host.as_str(), port))
            .await
            .map_err(WsError::Io)?,
    ))
}
