//! The TCP accept loop the server and the embedder endpoint serve through.
//!
//! Every accepted socket holds a connection permit for the whole life of the
//! connection: across keep-alive requests, and on through a WebSocket the
//! connection upgraded into. The permits are the descriptor floor, the one
//! bound that is the machine's: past it the socket in hand waits for a
//! connection to close and the loop stops accepting, so the sockets after it
//! wait in the kernel's backlog. They are queued, never refused.
//!
//! A connection from off this device that has not yet presented a credential
//! the server accepts is a stranger, and one peer address may hold only so
//! many strangers at once. A socket past that share is the anonymous surface
//! the rate law lets the server shed: it gets a 503 and is closed. A
//! connection leaves the share as soon as a request on it authenticates, and
//! from then on meets only the floor. Loopback meets only the floor.
//!
//! Request headers must arrive within a deadline, which also bounds an idle
//! keep-alive connection, and a request body that stops arriving while its
//! route waits for it is ended at an idle limit. All of it runs before any
//! route does, so it holds for a caller with no credential at all.
//!
//! The router still sees each request's peer as `ConnectInfo<SocketAddr>`,
//! which is what the caller-locality rule reads.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::{Pin, pin};
use std::sync::{Arc, Mutex, PoisonError};
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
use crate::wire_telemetry::{LimitQuestions, LimitRow};

/// The listener's bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ConnectionLimits {
    /// Connections open at once, from every peer together: the descriptor
    /// floor. Past it, new sockets wait in the backlog.
    pub(crate) max_connections: usize,
    /// Connections one off-device peer address may hold before any of them
    /// has authenticated, and never more than half of `max_connections`. A
    /// loopback peer is this device: the owner's own tools, or a reverse
    /// proxy whose callers all arrive from its one address. It has no share
    /// to keep.
    pub(crate) max_unauthenticated_per_peer: usize,
    /// How long a request's headers may take to arrive, counted from when the
    /// connection is ready to read them.
    pub(crate) header_read_timeout: Duration,
    /// How long a route may wait for the next piece of a request body before
    /// the body fails. A body that keeps arriving, however slowly, is never
    /// cut.
    pub(crate) body_idle_timeout: Duration,
    /// How long the loop waits for a free permit before it looks again.
    pub(crate) queue_wait: Duration,
}

/// What a stranger past its address's share reads before it is closed.
const SHED_RESPONSE: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nretry-after: 1\r\nconnection: close\r\ncontent-length: 0\r\n\r\n";

tokio::task_local! {
    /// The connection a request in flight arrived on.
    static CONNECTION: Arc<Connection>;
}

/// Says that the request in flight presented a credential the server
/// accepted, so its connection is no longer a stranger. Outside a request
/// this listener serves, it does nothing.
pub(crate) fn authenticated() {
    let _ = CONNECTION.try_with(|connection| {
        let share = connection
            .stranger
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        drop(share);
    });
}

/// Serves `app` on `listener` until `shutdown` resolves, then stops accepting,
/// asks every open connection to finish its request in flight, and returns
/// once they have closed. A WebSocket is not waited for: it ends with the
/// process. A crossed descriptor floor asks its question in `questions`.
pub(crate) async fn serve(
    listener: TcpListener,
    app: Router,
    limits: ConnectionLimits,
    questions: Arc<LimitQuestions>,
    shutdown: impl Future<Output = ()>,
) {
    let pool = ConnectionPool::new(&limits, questions);
    serve_with_pool(listener, app, &pool, limits, shutdown).await;
}

/// The descriptor floor and the strangers' shares one set of limits
/// describes. Listeners that serve from one pool share its bounds: two of
/// them never hold twice the connections, and an address's strangers are
/// counted across both.
pub(crate) struct ConnectionPool {
    floor: Admission<()>,
    strangers: Strangers,
}

impl ConnectionPool {
    pub(crate) fn new(limits: &ConnectionLimits, questions: Arc<LimitQuestions>) -> Self {
        Self {
            floor: Admission::<()>::new(
                LimitRow::Connections,
                questions,
                limits.max_connections,
                limits.queue_wait,
            ),
            strangers: Strangers::new(stranger_share(limits)),
        }
    }
}

/// [`serve`], taking its permits and strangers' places from `pool`.
pub(crate) async fn serve_with_pool(
    mut listener: TcpListener,
    app: Router,
    pool: &ConnectionPool,
    limits: ConnectionLimits,
    shutdown: impl Future<Output = ()>,
) {
    let ConnectionPool { floor, strangers } = pool;
    let (stopping, stop) = watch::channel(false);
    let (open, open_watch) = watch::channel(());
    let mut shutdown = pin!(shutdown);
    'serving: loop {
        let (stream, peer) = tokio::select! {
            accepted = axum::serve::Listener::accept(&mut listener) => accepted,
            () = &mut shutdown => break,
        };
        let address = peer.ip().to_canonical();
        let stranger = if address.is_loopback() {
            None
        } else {
            let Some(share) = strangers.take(address) else {
                tracing::debug!(
                    reason = "unauthenticated_connections_per_peer",
                    "connection shed at its address's unauthenticated share"
                );
                shed(stream);
                continue;
            };
            Some(share)
        };
        // Past the floor this socket waits for a connection to close, and
        // nothing more is accepted meanwhile: the next sockets wait in the
        // backlog.
        let permit = loop {
            tokio::select! {
                permit = floor.admit(()) => {
                    if let Ok(permit) = permit {
                        break permit;
                    }
                }
                () = &mut shutdown => break 'serving,
            }
        };
        let connection = Arc::new(Connection {
            stranger: Mutex::new(stranger),
        });
        let io = TokioIo::new(AdmittedStream {
            stream,
            _permit: permit,
        });
        let routes = TowerToHyperService::new(app.clone());
        let body_idle = limits.body_idle_timeout;
        // The id a reply no credential attributed names this socket by
        // (FIX 811): minted here, never derived from the peer's address.
        let socket_id = crate::api::call_receipt::mint_connection_id();
        let service = hyper::service::service_fn(move |request: hyper::Request<Incoming>| {
            let mut request = request.map(|body| Body::new(IdleBody::new(body, body_idle)));
            request.extensions_mut().insert(ConnectInfo(peer));
            CONNECTION.scope(
                Arc::clone(&connection),
                crate::api::call_receipt::on_connection(
                    socket_id,
                    hyper::service::Service::call(&routes, request),
                ),
            )
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

/// One accepted connection, as its requests see it.
struct Connection {
    /// Its place in its address's share while it has not authenticated.
    stranger: Mutex<Option<StrangerShare>>,
}

/// How many unauthenticated off-device connections each address holds.
#[derive(Clone)]
struct Strangers {
    held: Arc<Mutex<HashMap<IpAddr, usize>>>,
    per_peer: usize,
}

/// One address's share of strangers: as configured, but never more than
/// half the floor, so strangers from one address cannot fill the floor and
/// stop the loop before anyone else can reach it to authenticate.
fn stranger_share(limits: &ConnectionLimits) -> usize {
    limits
        .max_unauthenticated_per_peer
        .min(limits.max_connections / 2)
        .max(1)
}

/// One unauthenticated connection's place in its address's share. Dropping
/// it gives the place back.
struct StrangerShare {
    strangers: Strangers,
    address: IpAddr,
}

impl Strangers {
    fn new(per_peer: usize) -> Self {
        Self {
            held: Arc::default(),
            per_peer,
        }
    }

    /// A place for one more stranger from `address`, or `None` when it holds
    /// its whole share. Never a wait: this is the one bound that sheds.
    fn take(&self, address: IpAddr) -> Option<StrangerShare> {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let count = held.entry(address).or_default();
        if *count >= self.per_peer {
            return None;
        }
        *count += 1;
        Some(StrangerShare {
            strangers: self.clone(),
            address,
        })
    }
}

impl Drop for StrangerShare {
    fn drop(&mut self) {
        let mut held = self
            .strangers
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = held.get_mut(&self.address) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                held.remove(&self.address);
            }
        }
    }
}

/// Answers a stranger past its share with a 503 and closes it. Best effort
/// and never a wait: the write goes straight to the socket rather than through
/// the reactor, which has not yet seen a socket this fresh as writable, and a
/// socket whose buffer is full is simply closed. What request bytes have
/// already arrived are read off first, since closing over unread bytes resets
/// the connection and can take the 503 with it.
fn shed(stream: TcpStream) {
    if let Ok(stream) = stream.into_std() {
        let _ = io::Read::read(&mut &stream, &mut [0_u8; 4096]);
        let _ = io::Write::write(&mut &stream, SHED_RESPONSE);
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

/// `body` under this listener's body-idle limit ([`IdleBody`]), for the mesh
/// listener's requests (OF-535).
#[cfg(feature = "mesh")]
pub(crate) fn idle_body(body: Incoming, idle: Duration) -> Body {
    Body::new(IdleBody::new(body, idle))
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
    _permit: Permit,
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
pub(crate) mod tests;
