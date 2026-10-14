//! The TCP accept loop the server and the embedder endpoint serve through.
//!
//! Every accepted socket takes a connection permit before hyper reads a byte
//! of it, and the permit rides inside the socket, so it is held for the whole
//! life of the connection: across keep-alive requests, and on through a
//! WebSocket the connection upgraded into. A socket past the bound gets a 503
//! and is closed at once; it never waits in a queue. Request headers must
//! arrive within a deadline, which also bounds an idle keep-alive connection,
//! and a request body that stops arriving while its route waits for it is
//! ended at an idle limit. All of it runs before any route does, so it holds
//! for a caller with no credential at all.
//!
//! The router still sees each request's peer as `ConnectInfo<SocketAddr>`,
//! which is what the caller-locality rule reads.

use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::{Pin, pin};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::ConnectInfo;
use axum::{BoxError, Router};
use hyper::body::{Frame, Incoming, SizeHint};
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use crate::admission::{Admission, Permit};

/// The listener's bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ConnectionLimits {
    /// Connections open at once, from every peer together.
    pub(crate) max_connections: usize,
    /// Connections one off-device peer address may hold. A loopback peer is
    /// this device: the owner's own tools, or a reverse proxy whose callers
    /// all arrive from its one address. Only the total bounds it.
    pub(crate) max_connections_per_peer: usize,
    /// How long a request's headers may take to arrive, counted from when the
    /// connection is ready to read them.
    pub(crate) header_read_timeout: Duration,
    /// How long a route may wait for the next piece of a request body before
    /// the body fails. A body that keeps arriving, however slowly, is never
    /// cut.
    pub(crate) body_idle_timeout: Duration,
}

/// What a socket past the bound reads before it is closed.
const SATURATED_RESPONSE: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nretry-after: 1\r\nconnection: close\r\ncontent-length: 0\r\n\r\n";

/// Serves `app` on `listener` until `shutdown` resolves, then stops accepting,
/// asks every open connection to finish its request in flight, and returns
/// once they have closed. A WebSocket is not waited for: it ends with the
/// process.
pub(crate) async fn serve(
    mut listener: TcpListener,
    app: Router,
    limits: ConnectionLimits,
    shutdown: impl Future<Output = ()>,
) {
    let admission = Admission::new(limits.max_connections, limits.max_connections_per_peer);
    let (stopping, stop) = watch::channel(false);
    let (open, open_watch) = watch::channel(());
    let mut shutdown = pin!(shutdown);
    loop {
        let (stream, peer) = tokio::select! {
            accepted = axum::serve::Listener::accept(&mut listener) => accepted,
            () = &mut shutdown => break,
        };
        let admitted = if peer.ip().to_canonical().is_loopback() {
            admission.try_admit_unkeyed()
        } else {
            admission.try_admit(peer.ip().to_canonical())
        };
        let Ok(permit) = admitted else {
            tracing::debug!(
                reason = "connection_saturated",
                "connection refused at the listener bound"
            );
            shed(stream);
            continue;
        };
        let io = TokioIo::new(AdmittedStream {
            stream,
            _permit: permit,
        });
        let routes = TowerToHyperService::new(app.clone());
        let body_idle = limits.body_idle_timeout;
        let service = hyper::service::service_fn(move |request: hyper::Request<Incoming>| {
            let mut request = request.map(|body| Body::new(IdleBody::new(body, body_idle)));
            request.extensions_mut().insert(ConnectInfo(peer));
            hyper::service::Service::call(&routes, request)
        });
        let mut stop = stop.clone();
        let open = open_watch.clone();
        tokio::spawn(async move {
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder
                .timer(TokioTimer::new())
                .header_read_timeout(limits.header_read_timeout);
            let mut connection = pin!(builder.serve_connection(io, service).with_upgrades());
            // A closed or reset connection is the peer's business, not an
            // error of this server's.
            let stopped = tokio::select! {
                _ = connection.as_mut() => false,
                _ = stop.wait_for(|stopping| *stopping) => true,
            };
            if stopped {
                connection.as_mut().graceful_shutdown();
                let _ = connection.as_mut().await;
            }
            drop(open);
        });
    }
    let _ = stopping.send(true);
    drop(listener);
    drop(open_watch);
    open.closed().await;
}

/// Answers a socket past the bound with a 503 and closes it. Best effort and
/// never a wait: the write goes straight to the socket rather than through
/// the reactor, which has not yet seen a socket this fresh as writable, and a
/// socket whose buffer is full is simply closed. What request bytes have
/// already arrived are read off first, since closing over unread bytes resets
/// the connection and can take the 503 with it.
fn shed(stream: TcpStream) {
    if let Ok(stream) = stream.into_std() {
        let _ = io::Read::read(&mut &stream, &mut [0_u8; 4096]);
        let _ = io::Write::write(&mut &stream, SATURATED_RESPONSE);
    }
}

/// A request body that fails with `TimedOut` once a reader has waited `idle`
/// for its next frame. The clock runs only while the body is awaited and
/// restarts with every frame, so a slow reader costs the client nothing and a
/// client that finished its headers and then went quiet gives its connection
/// back.
struct IdleBody {
    body: Incoming,
    idle: Duration,
    waiting: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl IdleBody {
    fn new(body: Incoming, idle: Duration) -> Self {
        Self {
            body,
            idle,
            waiting: None,
        }
    }
}

impl hyper::body::Body for IdleBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        if let Poll::Ready(frame) = Pin::new(&mut this.body).poll_frame(cx) {
            this.waiting = None;
            return Poll::Ready(frame.map(|frame| frame.map_err(BoxError::from)));
        }
        let idle = this.idle;
        let waiting = this
            .waiting
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(idle)));
        if waiting.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        this.waiting = None;
        Poll::Ready(Some(Err(BoxError::from(io::Error::new(
            io::ErrorKind::TimedOut,
            "request body stalled",
        )))))
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

/// An accepted socket together with the permit that admitted it. The permit
/// goes when the socket does, whoever owns the socket by then.
struct AdmittedStream {
    stream: TcpStream,
    _permit: Permit<IpAddr>,
}

impl AsyncRead for AdmittedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for AdmittedStream {
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

#[cfg(test)]
mod tests;
