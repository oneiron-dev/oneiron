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

/// Opens `request`'s WebSocket on `dialer`'s carrier when there is one, else on
/// TCP to the request's host. TCP carries `ws` only: this build has no TLS, so
/// a `wss` URL is refused as `connect_async` refuses it. Returns the upgrade
/// response's headers beside the socket: the home names itself there.
pub(crate) async fn connect_sync_socket(
    request: impl IntoClientRequest + Unpin,
    dialer: Option<&dyn SyncDialer>,
) -> Result<(SyncSocket, tokio_tungstenite::tungstenite::http::HeaderMap), WsError> {
    let request = request.into_client_request()?;
    let io = match dialer {
        Some(dialer) => SyncIo::Dialed(dialer.dial().await.map_err(WsError::Io)?),
        None => {
            let uri = request.uri();
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
            SyncIo::Tcp(
                TcpStream::connect((host.as_str(), port))
                    .await
                    .map_err(WsError::Io)?,
            )
        }
    };
    let (socket, response) = tokio_tungstenite::client_async(request, io).await?;
    Ok((
        WireSocket::to_our_server(socket, MAX_CODEC_INNER_BYTES),
        response.into_parts().0.headers,
    ))
}
