//! The engine an app runs in its own process (OF-237): one shared Rust
//! entry point under every native binding.
//!
//! [`EmbeddedEngine::start`] opens the vault the way `oneiron serve` does,
//! as [`open_served_vault`] does with the app's keychain, its custody anchor
//! credential included (FIX 6516), then serves it over
//! a fresh [`EmbeddedHost`] and returns once the app's `ready` has run. A
//! binding shares the open vault ([`EmbeddedEngine::vault`]) with SDK
//! handles through `OneironClient::attach`, again for each new handle, and
//! never opens the path a second time. [`EmbeddedEngine::request`] carries
//! one buffered HTTP/1.1 exchange; `/ws` is not served through it, and a
//! reply over its cap is refused. [`EmbeddedEngine::request_streamed`] sends
//! the same request and hands back the reply as the server writes it, with
//! no whole-body buffer. [`EmbeddedEngine::connect`] opens a connection the
//! app holds instead: a raw byte stream into the same serve channel, served
//! as a socket's connection is, upgrades included, so `/ws` and a streamed
//! reply ride it.
//!
//! The artifact app (`/a/`) keeps its own origin: a second channel of each
//! serve run, which [`EmbeddedEngine::request_artifact`] and
//! [`EmbeddedEngine::connect_artifact`] reach. The API channel never carries
//! it.
//!
//! Every failure names its cause where the engine knows it
//! ([`super::EngineFailure`]), so a binding raises a stable code.
//!
//! [`EmbeddedEngine::stop`] is the app backgrounding: connections drain,
//! every worker stops, the vault stays open and the app's timer stays armed.
//! [`EmbeddedEngine::wake`] then serves again over that same vault before it
//! hands the Dreamer the wake, since the app's timer wakes an engine it has
//! backgrounded.
//!
//! The serve body runs on a thread of its own, as `oneiron serve` drives it
//! on its main thread, so the app's host callbacks run there or on the
//! thread that called [`start`], never on a runtime worker. It enters the
//! caller's runtime, or, when the app grants a bounded CPU share, a runtime
//! that serve run owns, whose worker threads that share caps (FIX 2661,
//! `super::runtime`).
//!
//! [`start`]: EmbeddedEngine::start

use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use axum::body::{Body, BodyDataStream, Bytes};
use futures_util::StreamExt as _;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use oneiron_vault_contract::host::{Host as _, HostLimits};
use oneiron_vault_contract::host_adapters::{AppHost, EmbeddedHost};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream, ReadHalf, WriteHalf};
use tokio::runtime::Handle;
use tokio::sync::{Mutex, mpsc, oneshot, watch};
use zeroize::Zeroizing;

use super::failure::{EngineErrorKind, cause, failure};
use crate::commands::{OpenedServedVault, open_served_vault_anchored};
use crate::config::{ServeArgs, ServeConfig};
use crate::owner::backup::CustodyAnchorCredentials;
use crate::owner::schedule::OwnerHost;

mod run;

use self::run::{State, spawn_run};

/// Connections an app may queue before the engine takes them.
const ENGINE_CONNECTION_BACKLOG: usize = 16;
/// Bytes one in-process connection buffers in each direction.
const ENGINE_DUPLEX_BUFFER_BYTES: usize = 64 * 1024;
/// The most bytes one [`EmbeddedConnection::receive`] returns: what the
/// connection buffers in one direction.
pub const ENGINE_RECEIVE_CHUNK_BYTES: usize = ENGINE_DUPLEX_BUFFER_BYTES;
/// The largest reply body a buffered request collects; a bigger one is an
/// error naming this cap.
const ENGINE_REPLY_BODY_CAP_BYTES: usize = 64 * 1024 * 1024;
/// The `Host` a request that names none carries: the app is this process.
const ENGINE_AUTHORITY: &str = "localhost";

/// One HTTP/1.1 request an app sends its engine.
pub struct EmbeddedRequest {
    pub method: String,
    /// Origin form: the path and query, such as `/.well-known/oneiron`.
    pub path: String,
    /// Sent as given, repeats and order kept; the caller brings its own
    /// auth.
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
}

/// The engine's reply. A 4xx or 5xx is a reply, not an error.
pub struct EmbeddedReply {
    pub status: u16,
    /// Every header the reply carried, repeats included.
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
}

/// The config `oneiron serve --config <config_file>` resolves (file,
/// environment, flags), for the vault at `vault_path`, with `dimensions`
/// when the binding names a width. Nothing else is overridden.
pub fn embedded_serve_config(
    vault_path: &Path,
    dimensions: Option<usize>,
    config_file: Option<&Path>,
) -> anyhow::Result<ServeConfig> {
    crate::config::resolve_serve_config(&ServeArgs {
        config: config_file.map(Path::to_path_buf),
        vault_path: Some(vault_path.to_path_buf()),
        dimensions,
        ..ServeArgs::default()
    })
    .context(cause(
        EngineErrorKind::Config,
        "the embedded engine's serve config did not resolve",
    ))
}

/// The limits an app grants its engine; an absent one is unbounded.
pub fn host_limits(memory_bytes: Option<u64>, cpu_millis_per_second: Option<u32>) -> HostLimits {
    let unbounded = HostLimits::unbounded();
    HostLimits {
        memory_bytes: memory_bytes.unwrap_or(unbounded.memory_bytes),
        cpu_millis_per_second: cpu_millis_per_second.unwrap_or(unbounded.cpu_millis_per_second),
    }
}

/// `at` in Unix milliseconds, as an app's timer takes it; a time before the
/// epoch is 0.
pub fn unix_millis(at: SystemTime) -> u64 {
    at.duration_since(UNIX_EPOCH).map_or(0, |since| {
        u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
    })
}

/// Refuses a call from inside an async runtime, where blocking on the
/// engine would stall it. An app host's callbacks run inside the engine's
/// runtime, so a callback that calls back into the engine is refused here
/// rather than left to deadlock.
pub fn ensure_app_thread() -> anyhow::Result<()> {
    if Handle::try_current().is_ok() {
        return Err(failure(
            EngineErrorKind::WrongThread,
            "the embedded engine blocks its caller; call it from an app thread, never from an async task or an app host callback",
        ));
    }
    Ok(())
}

/// The app's host, which also reports `ready` to the engine that started it.
struct Readied<A> {
    app: A,
    ready: Option<oneshot::Sender<()>>,
}

impl<A: AppHost> AppHost for Readied<A> {
    fn keychain(&mut self, name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        self.app.keychain(name)
    }

    fn schedule_wake(&mut self, at: Option<SystemTime>) -> anyhow::Result<()> {
        self.app.schedule_wake(at)
    }

    fn ready(&mut self) -> anyhow::Result<()> {
        self.app.ready()?;
        if let Some(ready) = self.ready.take() {
            let _ = ready.send(());
        }
        Ok(())
    }
}

/// The custody anchor door's owner credential the app keeps in its
/// keychain (FIX 6516), read only when `config`'s `[backup]` names a door:
/// the pipe's one object, under [`CustodyAnchorCredentials::KEYCHAIN_NAME`].
/// A keychain that keeps none leaves the door uncalled, as before; one that
/// does not decode is logged, never a byte of it, and the door is not called
/// either.
fn keychain_anchor<A: AppHost>(
    host: &mut EmbeddedHost<Readied<A>, DuplexStream>,
    config: &ServeConfig,
) -> Option<Arc<CustodyAnchorCredentials>> {
    config.backup.custody_anchor_url.as_ref()?;
    let held = host.secret(CustodyAnchorCredentials::KEYCHAIN_NAME).ok()?;
    match CustodyAnchorCredentials::from_keychain(&held) {
        Ok(credentials) => Some(Arc::new(credentials)),
        Err(reason) => {
            tracing::warn!(
                %reason,
                "the custody anchor credentials in the app's keychain were refused; the anchor \
                 door is not called"
            );
            None
        }
    }
}

/// A fresh host over `app`, and the signal its `ready` fires.
fn embedded_host<A: AppHost>(
    app: A,
    limits: HostLimits,
) -> (
    EmbeddedHost<Readied<A>, DuplexStream>,
    oneshot::Receiver<()>,
) {
    let (ready, readied) = oneshot::channel();
    let app = Readied {
        app,
        ready: Some(ready),
    };
    (
        EmbeddedHost::new(app, limits, ENGINE_CONNECTION_BACKLOG),
        readied,
    )
}

/// The engine inside an app's process, over the one vault it opened.
///
/// Its methods are async; run them on a multi-thread Tokio runtime outside
/// a `LocalSet`, as [`crate::build_app`] says. Serving runs on that runtime,
/// unless the app's limits grant a bounded CPU share: each serve run then
/// owns a runtime whose worker threads the share caps (FIX 2661). Dropped
/// while serving, it asks serving to stop and does not wait: call
/// [`EmbeddedEngine::close`] for the ordered stop.
pub struct EmbeddedEngine<A> {
    config: ServeConfig,
    limits: HostLimits,
    /// The worker cap of each serve run's own runtime, or `None` to serve on
    /// the caller's.
    serve_workers: Option<usize>,
    vault: Arc<oneiron::Vault>,
    /// The rehearsal config the opener resolved, which a restart's owner
    /// host takes, so nothing is resolved or opened twice.
    rehearsal: oneiron::VaultConfig,
    /// The custody anchor credential read at start, which a restart's owner
    /// host takes too.
    anchor: Option<Arc<CustodyAnchorCredentials>>,
    state: Mutex<State<A>>,
}

impl<A: AppHost + Clone + 'static> EmbeddedEngine<A> {
    /// Opens the vault `config` names and serves it over a host on `app`.
    ///
    /// A relay host's config is refused before anything opens. Returns once
    /// `app`'s `ready` has run, or with the serve body's startup error.
    pub async fn start(app: A, config: ServeConfig, limits: HostLimits) -> anyhow::Result<Self> {
        Self::start_serving_on(app, config, limits, super::runtime::worker_cap(limits)).await
    }

    /// [`Self::start`], each serve run on a runtime of its own capped at
    /// `serve_workers`, or, with `None`, on the caller's: a
    /// [`super::BlockingEngine`]'s own runtime already carries the cap.
    pub(super) async fn start_serving_on(
        app: A,
        config: ServeConfig,
        limits: HostLimits,
        serve_workers: Option<usize>,
    ) -> anyhow::Result<Self> {
        if config.privacy_posture == oneiron::HostingPrivacyPosture::Relay {
            return Err(failure(EngineErrorKind::RelayRefused, super::RELAY_REFUSAL));
        }
        let (mut host, readied) = embedded_host(app.clone(), limits);
        // Read once, at start, as the pipe is.
        let anchor = keychain_anchor(&mut host, &config);
        let OpenedServedVault { vault, owner_host } =
            open_served_vault_anchored(&mut host, &config, anchor.clone()).context(cause(
                EngineErrorKind::VaultOpen,
                "the embedded engine's vault did not open",
            ))?;
        let rehearsal = owner_host.vault_config.clone();
        let serving = spawn_run(
            host,
            Arc::clone(&vault),
            config.clone(),
            owner_host,
            serve_workers,
        )?;
        let mut state = State { app, serving: None };
        state.start_run(serving, readied).await?;
        Ok(Self {
            config,
            limits,
            serve_workers,
            vault,
            rehearsal,
            anchor,
            state: Mutex::new(state),
        })
    }

    /// The vault the engine opened, to share through `OneironClient::attach`
    /// at [`Self::path`] under the options the binding opened it with.
    pub fn vault(&self) -> &Arc<oneiron::Vault> {
        &self.vault
    }

    /// The vault's directory.
    pub fn path(&self) -> &Path {
        &self.config.vault_path
    }

    /// The config the engine serves.
    pub fn config(&self) -> &ServeConfig {
        &self.config
    }

    /// Sends one request over a fresh connection and collects the whole
    /// reply. Refused while the engine is stopped.
    pub async fn request(&self, request: EmbeddedRequest) -> anyhow::Result<EmbeddedReply> {
        exchange(&self.connector(Origin::Api).await?, request).await
    }

    /// [`Self::request`], with the reply handed back once its head arrives
    /// and its body read as the server writes it: no whole-body buffer, so
    /// the buffered reply's cap does not apply and the reader's own ceiling
    /// is the only one. Refused while the engine is stopped; a stop cuts the
    /// body off once the drain ends.
    pub async fn request_streamed(
        &self,
        request: EmbeddedRequest,
    ) -> anyhow::Result<EmbeddedReplyStream> {
        let response = send(&self.connector(Origin::Api).await?, request).await?;
        let (status, headers) = reply_head(&response);
        Ok(EmbeddedReplyStream {
            status,
            headers,
            body: EmbeddedBody(Body::new(response.into_body()).into_data_stream()),
        })
    }

    /// [`Self::request`] on the artifact app's own origin (`/a/`), apart
    /// from the API's: an app's web view loads artifacts through it.
    pub async fn request_artifact(
        &self,
        request: EmbeddedRequest,
    ) -> anyhow::Result<EmbeddedReply> {
        exchange(&self.connector(Origin::Artifacts).await?, request).await
    }

    /// Opens a connection the app holds: one fresh stream on the channel
    /// [`Self::request`] uses, which the server serves as a socket's
    /// connection, HTTP/1.1 with upgrades. The app writes the request (a
    /// `GET /ws` with its upgrade headers, or any other) and, after a `101`,
    /// the upgraded protocol; it reads what the server writes. Refused while
    /// the engine is stopped. A stop drains it as it drains a socket's
    /// connection, so after a wake the app connects again.
    pub async fn connect(&self) -> anyhow::Result<EmbeddedConnection> {
        let stream = dial(&self.connector(Origin::Api).await?).await?;
        Ok(EmbeddedConnection::new(stream))
    }

    /// [`Self::connect`] on the artifact app's own origin (`/a/`), apart from
    /// the API's. Refused while the engine is stopped.
    pub async fn connect_artifact(&self) -> anyhow::Result<EmbeddedConnection> {
        let stream = dial(&self.connector(Origin::Artifacts).await?).await?;
        Ok(EmbeddedConnection::new(stream))
    }

    /// The channel the running serve body takes `origin`'s connections on.
    async fn connector(&self, origin: Origin) -> anyhow::Result<mpsc::Sender<DuplexStream>> {
        self.state
            .lock()
            .await
            .serving
            .as_ref()
            .filter(|serving| !serving.stopping)
            .map(|serving| match origin {
                Origin::Api => serving.connector.clone(),
                Origin::Artifacts => serving.artifacts.clone(),
            })
            .ok_or_else(|| {
                failure(
                    EngineErrorKind::Stopped,
                    "the embedded engine is stopped; wake it first",
                )
            })
    }

    /// The app's timer fired, or a push arrived: run what is due. A stopped
    /// engine serves again first, over the same open vault, and returns once
    /// the app's `ready` has run.
    pub async fn wake(&self) -> anyhow::Result<()> {
        let mut state = self.state.lock().await;
        if let Some(serving) = &state.serving
            && !serving.ended()
            && !serving.stopping
        {
            serving.wake.notify_one();
            return Ok(());
        }
        // An ended run, or one a dropped stop left draining, is joined
        // before the next one starts (FIX 9484).
        if state.serving.is_some()
            && let Err(error) = state.join_serving().await
        {
            tracing::warn!(%error, "the embedded engine had stopped serving on its own");
        }
        let (host, readied) = embedded_host(state.app.clone(), self.limits);
        let owner_host = OwnerHost::from_config(&self.config, self.rehearsal.clone())
            .anchored_at(&self.config.backup, self.anchor.clone());
        let serving = spawn_run(
            host,
            Arc::clone(&self.vault),
            self.config.clone(),
            owner_host,
            self.serve_workers,
        )?;
        state.start_run(serving, readied).await?;
        if let Some(serving) = &state.serving {
            serving.wake.notify_one();
        }
        Ok(())
    }

    /// The app is backgrounding: stop taking connections, drain the open
    /// ones, stop every worker, and return once they have. The vault stays
    /// open for the next [`Self::wake`].
    pub async fn stop(&self) -> anyhow::Result<()> {
        self.state.lock().await.join_serving().await
    }

    /// Asks serving to stop without waiting for its drain (FIX 9485): a
    /// [`super::BlockingEngine`]'s close signals first, so the drain ends the
    /// calls that hold its engine before it waits to take the engine for
    /// the ordered stop, which joins this same run.
    pub(super) async fn signal_stop(&self) {
        if let Some(serving) = self.state.lock().await.serving.as_mut() {
            serving.signal_stop();
        }
    }

    /// Stops serving as [`Self::stop`] does, then releases the engine's
    /// share of the vault.
    pub async fn close(self) -> anyhow::Result<()> {
        self.stop().await
    }
}

/// Which of the engine's two origins a request or a connection rides.
#[derive(Clone, Copy)]
enum Origin {
    /// The API, `/ws` included.
    Api,
    /// The artifact app (`/a/`), on an origin of its own.
    Artifacts,
}

impl<A> Drop for EmbeddedEngine<A> {
    fn drop(&mut self) {
        if let Some(serving) = self.state.get_mut().serving.take() {
            serving.stop.notify_one();
        }
    }
}

/// A fresh duplex stream: the server's end handed to the engine's channel,
/// the app's end returned.
async fn dial(connector: &mpsc::Sender<DuplexStream>) -> anyhow::Result<DuplexStream> {
    let (client, server) = tokio::io::duplex(ENGINE_DUPLEX_BUFFER_BYTES);
    connector.send(server).await.map_err(|_| {
        failure(
            EngineErrorKind::ConnectionEnded,
            "the embedded engine stopped taking connections",
        )
    })?;
    Ok(client)
}

/// One exchange over a fresh duplex stream handed to the engine's channel.
async fn exchange(
    connector: &mpsc::Sender<DuplexStream>,
    request: EmbeddedRequest,
) -> anyhow::Result<EmbeddedReply> {
    let response = send(connector, request).await?;
    let (status, headers) = reply_head(&response);
    let body = reply_body(response.into_body()).await?;
    Ok(EmbeddedReply {
        status,
        headers,
        body,
    })
}

/// Sends `request` over a fresh duplex stream handed to the engine's channel
/// and returns the reply once its head arrives, its body unread.
async fn send(
    connector: &mpsc::Sender<DuplexStream>,
    request: EmbeddedRequest,
) -> anyhow::Result<hyper::Response<Incoming>> {
    let request = http_request(request)?;
    let client = dial(connector).await?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake::<_, Body>(TokioIo::new(client))
            .await
            .context(cause(
                EngineErrorKind::ConnectionEnded,
                "the embedded engine's connection did not open",
            ))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    sender.send_request(request).await.context(cause(
        EngineErrorKind::ConnectionEnded,
        "the embedded engine did not answer the request",
    ))
}

/// A reply's status and every header it carried, repeats included.
fn reply_head(response: &hyper::Response<Incoming>) -> (u16, Vec<(String, Vec<u8>)>) {
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
        .collect();
    (response.status().as_u16(), headers)
}

/// The request as hyper sends it. A request that names no `Host` takes
/// [`ENGINE_AUTHORITY`]; an upgrade is refused, since this exchange is
/// buffered.
fn http_request(request: EmbeddedRequest) -> anyhow::Result<hyper::Request<Body>> {
    let EmbeddedRequest {
        method,
        path,
        headers,
        body,
    } = request;
    if !path.starts_with('/') {
        return Err(failure(
            EngineErrorKind::BadRequest,
            "an embedded request's path is origin form and starts with `/`",
        ));
    }
    let mut has_host = false;
    let mut builder = hyper::Request::builder().method(method.as_str()).uri(path);
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("upgrade") {
            return Err(failure(
                EngineErrorKind::BadRequest,
                "an embedded request is buffered; an upgrade such as `/ws` is not served through it",
            ));
        }
        has_host |= name.eq_ignore_ascii_case("host");
        builder = builder.header(name, value);
    }
    if !has_host {
        builder = builder.header(hyper::header::HOST, ENGINE_AUTHORITY);
    }
    builder.body(Body::from(body)).context(cause(
        EngineErrorKind::BadRequest,
        "an embedded request's method, path or header is malformed",
    ))
}

/// The whole reply body, up to [`ENGINE_REPLY_BODY_CAP_BYTES`].
async fn reply_body(body: Incoming) -> anyhow::Result<Vec<u8>> {
    let mut chunks = EmbeddedBody(Body::new(body).into_data_stream());
    let mut collected = Vec::new();
    while let Some(chunk) = chunks.next_chunk().await? {
        if collected.len().saturating_add(chunk.len()) > ENGINE_REPLY_BODY_CAP_BYTES {
            return Err(failure(
                EngineErrorKind::ReplyTooLarge,
                format!(
                    "the embedded engine's reply body is over the {ENGINE_REPLY_BODY_CAP_BYTES}-byte cap of a buffered request"
                ),
            ));
        }
        collected.extend_from_slice(&chunk);
    }
    Ok(collected)
}

/// A reply whose body arrives as the server writes it
/// ([`EmbeddedEngine::request_streamed`]). A 4xx or 5xx status is a reply,
/// not an error.
pub struct EmbeddedReplyStream {
    pub status: u16,
    /// Every header the reply carried, repeats included.
    pub headers: Vec<(String, Vec<u8>)>,
    /// The body, chunk by chunk.
    pub body: EmbeddedBody,
}

/// A streamed reply's body ([`EmbeddedReplyStream::body`]).
pub struct EmbeddedBody(BodyDataStream);

impl EmbeddedBody {
    /// The next chunk the server wrote, waiting until one arrives; `None`
    /// once the body has ended. An error is a body cut off before its end.
    pub async fn next_chunk(&mut self) -> anyhow::Result<Option<Bytes>> {
        match self.0.next().await {
            Some(chunk) => chunk.map(Some).context(cause(
                EngineErrorKind::ConnectionEnded,
                "the embedded engine's reply broke off",
            )),
            None => Ok(None),
        }
    }
}

/// One connection an app holds to its engine ([`EmbeddedEngine::connect`]):
/// bytes both ways over one in-process stream the server serves as a
/// socket's connection.
///
/// A send and a receive may wait at once, from two tasks. [`Self::close`]
/// ends the app's side: a waiting receive returns empty, a waiting send is
/// refused, and the server reads the end of the stream.
pub struct EmbeddedConnection {
    reader: Mutex<ReadHalf<DuplexStream>>,
    writer: Mutex<WriteHalf<DuplexStream>>,
    closed: watch::Sender<bool>,
}

impl EmbeddedConnection {
    fn new(stream: DuplexStream) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
            closed: watch::Sender::new(false),
        }
    }

    /// Writes all of `bytes` to the server. Refused once closed, or once the
    /// server has ended the connection.
    pub async fn send(&self, bytes: &[u8]) -> anyhow::Result<()> {
        let mut closed = self.closed.subscribe();
        let mut writer = self.writer.lock().await;
        tokio::select! {
            written = async {
                writer.write_all(bytes).await?;
                writer.flush().await
            } => written.context(cause(
                EngineErrorKind::ConnectionEnded,
                "the embedded engine ended the connection",
            )),
            _ = closed.wait_for(|closed| *closed) => Err(failure(
                EngineErrorKind::ConnectionEnded,
                "the engine connection is closed",
            )),
        }
    }

    /// The next bytes the server wrote, at most
    /// [`ENGINE_RECEIVE_CHUNK_BYTES`]; it waits until some arrive. Empty once
    /// the server has ended the connection or this side has closed it.
    pub async fn receive(&self) -> anyhow::Result<Vec<u8>> {
        let mut closed = self.closed.subscribe();
        let mut reader = self.reader.lock().await;
        let mut buffer = vec![0; ENGINE_RECEIVE_CHUNK_BYTES];
        tokio::select! {
            read = reader.read(&mut buffer) => {
                let read = read.context(cause(
                    EngineErrorKind::ConnectionEnded,
                    "the embedded engine's connection broke off",
                ))?;
                buffer.truncate(read);
                Ok(buffer)
            }
            _ = closed.wait_for(|closed| *closed) => Ok(Vec::new()),
        }
    }

    /// Ends the app's side: no send after it, a waiting receive returns
    /// empty, and the server reads the end of the stream. Closing again does
    /// nothing.
    pub async fn close(&self) {
        if self.closed.send_replace(true) {
            return;
        }
        // A server that already ended the connection has nothing left to
        // read, so a failed shutdown changes nothing.
        let _ = self.writer.lock().await.shutdown().await;
    }
}
