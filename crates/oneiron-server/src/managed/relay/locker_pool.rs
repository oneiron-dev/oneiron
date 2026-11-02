//! The relay locker's connections in a pressure check (FIX 7739), the one a
//! vault server's public listener keeps over its pool (FIX 7656).
//!
//! The locker serves on its own listener with no descriptor floor and no
//! clock on a request. This counts its open connections, and each request
//! body the room's access token let in, from its first byte to its last:
//! while the open connections are as many as the public listener's floor
//! would hold, the check is raised and says so once, and it clears below
//! that. It only observes: nothing waits, nothing is cut or refused. The
//! room's operator reads it at `GET /v1/relay/{vault}/pressure`.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};

use axum::body::{Body, Bytes};
use axum::extract::Request;
use axum::extract::connect_info::{ConnectInfo, Connected};
use axum::middleware::Next;
use axum::response::Response;
use axum::serve::IncomingStream;
use hyper::body::{Body as _, Frame, SizeHint};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

use crate::wire_telemetry::{
    ConnectionPoolPressure, ObservedBody, ObservedSocket, PoolPressure, SocketHold,
};

/// The locker's open connections and the check they raise.
pub(super) struct LockerPool {
    pressure: Arc<PoolPressure>,
    /// The public listener's descriptor floor (`[limits] max_connections`
    /// as it defaults on this machine): as many open connections raise the
    /// check.
    bound: usize,
    open: Mutex<OpenCount>,
}

#[derive(Default)]
struct OpenCount {
    open: usize,
    /// The latest time the open connections reached `bound`.
    episode: u64,
}

impl LockerPool {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            pressure: PoolPressure::relay_locker(),
            bound: crate::config::LimitsConfig::default()
                .max_connections
                .max(1),
            open: Mutex::default(),
        })
    }

    /// The check as it stands now.
    pub(super) fn reading(&self) -> ConnectionPoolPressure {
        self.pressure.snapshot()
    }

    /// One more open connection: reaching the bound raises the check.
    fn opened(self: &Arc<Self>) -> OpenConnection {
        let mut count = self.open.lock().unwrap_or_else(PoisonError::into_inner);
        count.open += 1;
        if count.open == self.bound {
            count.episode += 1;
            self.pressure.raise(count.episode, self.bound as u64);
        }
        drop(count);
        OpenConnection {
            pool: Arc::clone(self),
            observed: self.pressure.socket(SocketHold::Floor),
        }
    }
}

/// One open connection's place in the count and in the check. Dropped
/// with its socket; falling below the bound clears the check.
pub(super) struct OpenConnection {
    pool: Arc<LockerPool>,
    observed: ObservedSocket,
}

impl Drop for OpenConnection {
    fn drop(&mut self) {
        let pool = &self.pool;
        let mut count = pool.open.lock().unwrap_or_else(PoisonError::into_inner);
        if count.open == pool.bound {
            pool.pressure.drain(count.episode);
        }
        count.open = count.open.saturating_sub(1);
    }
}

/// The locker's TCP listener, each socket it accepts counted while open.
pub(super) struct LockerListener {
    listener: TcpListener,
    pool: Arc<LockerPool>,
}

impl LockerListener {
    pub(super) fn new(listener: TcpListener, pool: Arc<LockerPool>) -> Self {
        Self { listener, pool }
    }
}

impl axum::serve::Listener for LockerListener {
    type Io = LockerSocket;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let (stream, peer) = axum::serve::Listener::accept(&mut self.listener).await;
        let open = Arc::new(self.pool.opened());
        (LockerSocket { stream, open }, peer)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}

/// An accepted socket and its place in the count, which go together.
pub(super) struct LockerSocket {
    stream: TcpStream,
    open: Arc<OpenConnection>,
}

/// The connection a request arrived on, as the locker's routes see it.
#[derive(Clone)]
pub(super) struct LockerConnection(Arc<OpenConnection>);

impl Connected<IncomingStream<'_, LockerListener>> for LockerConnection {
    fn connect_info(stream: IncomingStream<'_, LockerListener>) -> Self {
        Self(Arc::clone(&stream.io().open))
    }
}

/// Counts an authorized request's body in the check while it arrives.
pub(super) async fn count_body(
    ConnectInfo(connection): ConnectInfo<LockerConnection>,
    request: Request,
    next: Next,
) -> Response {
    let (parts, body) = request.into_parts();
    let counted = (!body.is_end_stream()).then(|| connection.0.observed.body().0);
    let body = Body::new(CountedBody { body, counted });
    next.run(Request::from_parts(parts, body)).await
}

/// A request body whose record in the check ends with its last frame, its
/// end, its error or its drop.
struct CountedBody {
    body: Body,
    counted: Option<ObservedBody>,
}

impl hyper::body::Body for CountedBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.body).poll_frame(cx);
        if let Poll::Ready(frame) = &polled {
            if let (Some(counted), Some(Ok(frame))) = (&this.counted, frame) {
                counted.carried(frame.data_ref().map_or(0, Bytes::len));
            }
            if !matches!(frame, Some(Ok(_))) || this.body.is_end_stream() {
                this.counted = None;
            }
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

impl AsyncRead for LockerSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for LockerSocket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}
