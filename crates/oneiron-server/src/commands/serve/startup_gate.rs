//! The API listener's answers from bind until serve's startup work ends
//! (FIX 22117).
//!
//! Serve binds its listeners and logs `listening` before it attaches its
//! workers, the mesh, device sync and the shared environments, which can take
//! seconds. The gate accepts on the bound API listener for that time, so a
//! client's connect is answered rather than left in the kernel's backlog:
//!
//! - `GET /api/health` answers 200 with `status: "starting"`, never `"ok"`;
//!   the real router's own health says `"ok"` once it serves.
//! - A connection-upgrade request gets a 503 with `Retry-After: 1`, so its
//!   client reconnects to the real accept loop.
//! - Every other request is held until startup ends. Then it runs on the real
//!   router unchanged, or, when startup failed, gets a 503 in the server's
//!   JSON error shape.
//!
//! Each gate connection serves one HTTP/1.1 request and closes: keep-alive is
//! off and every reply says `Connection: close`, so the client's next request
//! reaches the real loop and its connection pool. At most the configured
//! connection floor of gate connections are open at once; a connection past
//! it is dropped. Request headers meet the listener's header-read deadline,
//! and a held request's body its body-idle limit, once its route reads it.
//!
//! At hand-over the gate stops accepting and gives the listener back to
//! serve. Connections it already accepted finish in their own tasks.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::ConnectInfo;
use axum::http::header::{CONNECTION, RETRY_AFTER, UPGRADE};
use axum::http::{HeaderValue, Method};
use axum::response::{IntoResponse, Response};
use hyper::body::Incoming;
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinHandle;

use crate::error::{ApiError, ApiErrorDetails};
use crate::http_listener::ConnectionLimits;

/// The one route the gate answers itself while startup runs.
const HEALTH_PATH: &str = "/api/health";

/// Where serve's startup stands, as the gate's connections read it.
enum Startup {
    /// The startup work still runs: requests wait.
    Running,
    /// Startup succeeded: requests run on this router, the one the real
    /// accept loop serves.
    Served(Router),
    /// Startup failed: requests get a 503.
    Failed,
}

impl Startup {
    fn ended(&self) -> bool {
        !matches!(self, Self::Running)
    }
}

/// The accept loop serve runs on its API listener while it starts. Dropped
/// without [`Self::hand_over`] or [`Self::fail`], as a startup error serve
/// returns at once drops it, it reads as a failed start.
pub(super) struct StartupGate {
    startup: watch::Sender<Startup>,
    accepting: JoinHandle<TcpListener>,
}

impl StartupGate {
    /// Starts answering on `listener` at once, within `limits`' connection
    /// floor, header-read deadline and body-idle limit.
    pub(super) fn spawn(listener: TcpListener, limits: ConnectionLimits) -> Self {
        let (startup, watched) = watch::channel(Startup::Running);
        let accepting = tokio::spawn(accept(listener, watched, limits));
        Self { startup, accepting }
    }

    /// Installs `app`, which releases every held request onto it, stops the
    /// accept loop and returns the listener for the real loop to serve.
    pub(super) async fn hand_over(self, app: Router) -> TcpListener {
        self.startup.send_replace(Startup::Served(app));
        match self.accepting.await {
            Ok(listener) => listener,
            // Nothing aborts the loop, so its join error is its panic.
            Err(error) => std::panic::resume_unwind(error.into_panic()),
        }
    }

    /// Answers every held request with a 503 and stops the accept loop,
    /// which closes the listener.
    pub(super) async fn fail(self) {
        self.startup.send_replace(Startup::Failed);
        if let Err(error) = self.accepting.await {
            tracing::warn!(%error, "the startup gate's accept loop panicked");
        }
    }
}

/// Accepts on `listener` until startup ends, then returns it. Each
/// connection is a task of its own, which outlives the loop.
async fn accept(
    mut listener: TcpListener,
    mut startup: watch::Receiver<Startup>,
    limits: ConnectionLimits,
) -> TcpListener {
    let places = Arc::new(Semaphore::new(
        limits.max_connections.min(Semaphore::MAX_PERMITS),
    ));
    loop {
        let (stream, peer) = tokio::select! {
            biased;
            // A gate dropped before startup ended stops here too.
            _ = startup.wait_for(Startup::ended) => break,
            accepted = axum::serve::Listener::accept(&mut listener) => accepted,
        };
        let Ok(place) = Arc::clone(&places).try_acquire_owned() else {
            tracing::debug!(
                reason = "startup_gate_connections",
                "connection dropped at the startup gate's connection floor"
            );
            drop(stream);
            continue;
        };
        let watched = startup.clone();
        let body_idle = limits.body_idle_timeout;
        let service = hyper::service::service_fn(move |request: hyper::Request<Incoming>| {
            let reply = answer(request, peer, watched.clone(), body_idle);
            async move { Ok::<_, Infallible>(reply.await) }
        });
        let header_read_timeout = limits.header_read_timeout;
        tokio::spawn(async move {
            let _place = place;
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder
                .timer(TokioTimer::new())
                .header_read_timeout(header_read_timeout)
                .keep_alive(false);
            // A closed or reset connection is the peer's business, not an
            // error of this server's.
            let _ = builder
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
    listener
}

/// The reply to one request on a gate connection, which closes after it.
async fn answer(
    request: hyper::Request<Incoming>,
    peer: SocketAddr,
    mut startup: watch::Receiver<Startup>,
    body_idle: Duration,
) -> Response {
    // A gate dropped while startup ran is a failed start, never a starting one.
    let starting = startup.has_changed().is_ok() && !startup.borrow().ended();
    let mut reply = if request.headers().contains_key(UPGRADE) {
        reconnect_reply()
    } else if starting && request.method() == Method::GET && request.uri().path() == HEALTH_PATH {
        starting_health()
    } else {
        held(request, peer, &mut startup, body_idle).await
    };
    reply
        .headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("close"));
    reply
}

/// `request` once startup ends: run on the real router as its own accept loop
/// would run it, with its peer, connection id, body-idle limit and explicit
/// credential revocation, or a 503 when startup failed.
async fn held(
    request: hyper::Request<Incoming>,
    peer: SocketAddr,
    startup: &mut watch::Receiver<Startup>,
    body_idle: Duration,
) -> Response {
    let ended = startup.wait_for(Startup::ended).await.is_ok();
    let router = if ended { served_router(startup) } else { None };
    let Some(router) = router else {
        return start_failed_reply();
    };
    let (mut parts, body) = request.into_parts();
    parts.extensions.insert(ConnectInfo(peer));
    let request = hyper::Request::from_parts(parts, body);
    // The real loop's dispatch: body-idle limit and the request's explicit
    // credential revocation, checked before each body frame.
    crate::api::call_receipt::on_connection(
        crate::api::call_receipt::mint_connection_id(),
        crate::http_listener::route_revocable(router, request, body_idle),
    )
    .await
}

/// The router startup installed, or `None` once it failed.
fn served_router(startup: &watch::Receiver<Startup>) -> Option<Router> {
    match &*startup.borrow() {
        Startup::Served(router) => Some(router.clone()),
        Startup::Running | Startup::Failed => None,
    }
}

/// `/api/health` while startup runs: the service answers, and says it is
/// not ready yet.
#[derive(Serialize)]
struct StartingHealth {
    status: &'static str,
    service: &'static str,
}

fn starting_health() -> Response {
    axum::Json(StartingHealth {
        status: "starting",
        service: "oneiron-server",
    })
    .into_response()
}

/// A held request's reply when startup failed: serve is returning its error
/// and stops.
fn start_failed_reply() -> Response {
    ApiError::new(
        "the server did not finish starting",
        ApiErrorDetails::MirrorNotReady { mirror: None },
        ["Start the server again; its log names the startup error."],
    )
    .into_response()
}

/// A connection-upgrade request's reply while startup runs: the gate serves
/// no upgrade, so the client reconnects to the real accept loop.
fn reconnect_reply() -> Response {
    let mut reply = ApiError::new(
        "the server is still starting",
        ApiErrorDetails::MirrorNotReady { mirror: None },
        ["Reconnect after the time Retry-After names."],
    )
    .into_response();
    reply
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static("1"));
    reply
}
