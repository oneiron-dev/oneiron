//! The engine an app runs in its own process (OF-237): one shared Rust
//! entry point under every native binding.
//!
//! [`EmbeddedEngine::start`] opens the vault the way `oneiron serve` does,
//! through [`open_served_vault`] and the app's keychain, then serves it over
//! a fresh [`EmbeddedHost`] and returns once the app's `ready` has run. A
//! binding shares the open vault ([`EmbeddedEngine::vault`]) with SDK
//! handles through `OneironClient::attach`, again for each new handle, and
//! never opens the path a second time. [`EmbeddedEngine::request`] carries
//! one buffered HTTP/1.1 exchange; `/ws` and streamed bodies are not served
//! through it.
//!
//! [`EmbeddedEngine::stop`] is the app backgrounding: connections drain,
//! every worker stops, the vault stays open and the app's timer stays armed.
//! [`EmbeddedEngine::wake`] then serves again over that same vault before it
//! hands the Dreamer the wake, since the app's timer wakes an engine it has
//! backgrounded.
//!
//! The serve body runs on a thread of its own, entered into the caller's
//! runtime as `oneiron serve` drives it on its main thread, so the app's
//! host callbacks run there or on the thread that called [`start`], never on
//! a runtime worker.
//!
//! [`start`]: EmbeddedEngine::start

use std::path::Path;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use axum::body::Body;
use futures_util::StreamExt as _;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use oneiron_vault_contract::host::HostLimits;
use oneiron_vault_contract::host_adapters::{AppHost, EmbeddedHost};
use tokio::io::DuplexStream;
use tokio::runtime::{Handle, Runtime};
use tokio::sync::{Mutex, Notify, mpsc, oneshot};
use zeroize::Zeroizing;

use crate::commands::{OpenedServedVault, open_served_vault};
use crate::config::{ServeArgs, ServeConfig};
use crate::owner::schedule::OwnerHost;

/// Connections an app may queue before the engine takes them.
const ENGINE_CONNECTION_BACKLOG: usize = 16;
/// Bytes one in-process connection buffers in each direction.
const ENGINE_DUPLEX_BUFFER_BYTES: usize = 64 * 1024;
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
    anyhow::ensure!(
        Handle::try_current().is_err(),
        "the embedded engine blocks its caller; call it from an app thread, never from an async task or an app host callback"
    );
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

/// One run of the serve body, from ready until it returns.
struct Serving {
    connector: mpsc::Sender<DuplexStream>,
    wake: Arc<Notify>,
    stop: Arc<Notify>,
    done: oneshot::Receiver<anyhow::Result<()>>,
}

impl Serving {
    /// Stops serving and waits out the ordered drain and worker shutdown.
    async fn finish(self) -> anyhow::Result<()> {
        self.stop.notify_one();
        self.done.await.unwrap_or_else(|_| {
            Err(anyhow::anyhow!(
                "the embedded engine's serve thread panicked"
            ))
        })
    }

    /// The serve body returned, or is returning: it takes no connection.
    fn ended(&self) -> bool {
        self.connector.is_closed()
    }
}

/// Starts the serve body over `vault` on a thread of its own and waits for
/// the app's `ready`, or for the body's startup error.
async fn serve_on<A: AppHost + 'static>(
    host: EmbeddedHost<Readied<A>, DuplexStream>,
    mut readied: oneshot::Receiver<()>,
    vault: Arc<oneiron::Vault>,
    config: ServeConfig,
    owner_host: OwnerHost,
) -> anyhow::Result<Serving> {
    let connector = host.connector();
    let (wake, stop) = (host.wake_handle(), host.stop_handle());
    let (finished, mut done) = oneshot::channel();
    let runtime = Handle::current();
    std::thread::Builder::new()
        .name("oneiron-engine-serve".to_owned())
        .spawn(move || {
            let served =
                runtime.block_on(super::serve_prepared(host, vault, config, None, owner_host));
            let _ = finished.send(served);
        })
        .context("the embedded engine's serve thread did not start")?;
    let ready = tokio::select! {
        biased;
        ready = &mut readied => ready.is_ok(),
        served = &mut done => return Err(startup_failure(served)),
    };
    if !ready {
        return Err(startup_failure(done.await));
    }
    Ok(Serving {
        connector,
        wake,
        stop,
        done,
    })
}

/// Why serving ended before the app's `ready` ran.
fn startup_failure(served: Result<anyhow::Result<()>, oneshot::error::RecvError>) -> anyhow::Error {
    match served {
        Ok(Err(error)) => error.context("the embedded engine did not start"),
        Ok(Ok(())) => anyhow::anyhow!("the embedded engine stopped before it was ready"),
        Err(_) => {
            anyhow::anyhow!("the embedded engine's serve thread panicked before it was ready")
        }
    }
}

/// What serving holds between a stop and a wake.
struct State<A> {
    app: A,
    serving: Option<Serving>,
}

/// The engine inside an app's process, over the one vault it opened.
///
/// Its methods are async; run them on a multi-thread Tokio runtime outside
/// a `LocalSet`, as [`crate::build_app`] says. Dropped while serving, it
/// asks serving to stop and does not wait: call [`EmbeddedEngine::close`]
/// for the ordered stop.
pub struct EmbeddedEngine<A> {
    config: ServeConfig,
    limits: HostLimits,
    vault: Arc<oneiron::Vault>,
    /// The rehearsal config the opener resolved, which a restart's owner
    /// host takes, so nothing is resolved or opened twice.
    rehearsal: oneiron::VaultConfig,
    state: Mutex<State<A>>,
}

impl<A: AppHost + Clone + 'static> EmbeddedEngine<A> {
    /// Opens the vault `config` names and serves it over a host on `app`.
    ///
    /// A relay host's config is refused before anything opens. Returns once
    /// `app`'s `ready` has run, or with the serve body's startup error.
    pub async fn start(app: A, config: ServeConfig, limits: HostLimits) -> anyhow::Result<Self> {
        anyhow::ensure!(
            config.privacy_posture != oneiron::HostingPrivacyPosture::Relay,
            super::RELAY_REFUSAL
        );
        let (mut host, readied) = embedded_host(app.clone(), limits);
        let OpenedServedVault { vault, owner_host } = open_served_vault(&mut host, &config)?;
        let rehearsal = owner_host.vault_config.clone();
        let serving = serve_on(
            host,
            readied,
            Arc::clone(&vault),
            config.clone(),
            owner_host,
        )
        .await?;
        Ok(Self {
            config,
            limits,
            vault,
            rehearsal,
            state: Mutex::new(State {
                app,
                serving: Some(serving),
            }),
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
        let connector = self
            .state
            .lock()
            .await
            .serving
            .as_ref()
            .map(|serving| serving.connector.clone())
            .ok_or_else(|| anyhow::anyhow!("the embedded engine is stopped; wake it first"))?;
        exchange(&connector, request).await
    }

    /// The app's timer fired, or a push arrived: run what is due. A stopped
    /// engine serves again first, over the same open vault, and returns once
    /// the app's `ready` has run.
    pub async fn wake(&self) -> anyhow::Result<()> {
        let mut state = self.state.lock().await;
        if let Some(serving) = &state.serving
            && !serving.ended()
        {
            serving.wake.notify_one();
            return Ok(());
        }
        if let Some(ended) = state.serving.take()
            && let Err(error) = ended.finish().await
        {
            tracing::warn!(%error, "the embedded engine had stopped serving on its own");
        }
        let (host, readied) = embedded_host(state.app.clone(), self.limits);
        let owner_host = OwnerHost::from_config(&self.config, self.rehearsal.clone());
        let serving = serve_on(
            host,
            readied,
            Arc::clone(&self.vault),
            self.config.clone(),
            owner_host,
        )
        .await?;
        serving.wake.notify_one();
        state.serving = Some(serving);
        Ok(())
    }

    /// The app is backgrounding: stop taking connections, drain the open
    /// ones, stop every worker, and return once they have. The vault stays
    /// open for the next [`Self::wake`].
    pub async fn stop(&self) -> anyhow::Result<()> {
        let mut state = self.state.lock().await;
        match state.serving.take() {
            Some(serving) => serving.finish().await,
            None => Ok(()),
        }
    }

    /// Stops serving as [`Self::stop`] does, then releases the engine's
    /// share of the vault.
    pub async fn close(self) -> anyhow::Result<()> {
        self.stop().await
    }
}

impl<A> Drop for EmbeddedEngine<A> {
    fn drop(&mut self) {
        if let Some(serving) = self.state.get_mut().serving.take() {
            serving.stop.notify_one();
        }
    }
}

/// One exchange over a fresh duplex stream handed to the engine's channel.
async fn exchange(
    connector: &mpsc::Sender<DuplexStream>,
    request: EmbeddedRequest,
) -> anyhow::Result<EmbeddedReply> {
    let request = http_request(request)?;
    let (client, server) = tokio::io::duplex(ENGINE_DUPLEX_BUFFER_BYTES);
    connector
        .send(server)
        .await
        .map_err(|_| anyhow::anyhow!("the embedded engine stopped taking connections"))?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake::<_, Body>(TokioIo::new(client)).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let response = sender.send_request(request).await?;
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
        .collect();
    let body = reply_body(response.into_body()).await?;
    Ok(EmbeddedReply {
        status,
        headers,
        body,
    })
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
    anyhow::ensure!(
        path.starts_with('/'),
        "an embedded request's path is origin form and starts with `/`"
    );
    let mut has_host = false;
    let mut builder = hyper::Request::builder().method(method.as_str()).uri(path);
    for (name, value) in headers {
        anyhow::ensure!(
            !name.eq_ignore_ascii_case("upgrade"),
            "an embedded request is buffered; an upgrade such as `/ws` is not served through it"
        );
        has_host |= name.eq_ignore_ascii_case("host");
        builder = builder.header(name, value);
    }
    if !has_host {
        builder = builder.header(hyper::header::HOST, ENGINE_AUTHORITY);
    }
    Ok(builder.body(Body::from(body))?)
}

/// The whole reply body, up to [`ENGINE_REPLY_BODY_CAP_BYTES`].
async fn reply_body(body: Incoming) -> anyhow::Result<Vec<u8>> {
    let mut chunks = Body::new(body).into_data_stream();
    let mut collected = Vec::new();
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk.context("the embedded engine's reply broke off")?;
        anyhow::ensure!(
            collected.len().saturating_add(chunk.len()) <= ENGINE_REPLY_BODY_CAP_BYTES,
            "the embedded engine's reply body is over the {ENGINE_REPLY_BODY_CAP_BYTES}-byte cap of a buffered request"
        );
        collected.extend_from_slice(&chunk);
    }
    Ok(collected)
}

/// An engine and the runtime it runs on, while it runs.
struct Running<A> {
    engine: EmbeddedEngine<A>,
    runtime: Runtime,
}

impl<A: AppHost + Clone + 'static> Running<A> {
    /// The ordered stop, then the runtime, last.
    fn close(self) -> anyhow::Result<()> {
        let Self { engine, runtime } = self;
        let closed = runtime.block_on(engine.close());
        drop(runtime);
        closed
    }
}

/// An [`EmbeddedEngine`] on a multi-thread Tokio runtime it owns, for a
/// binding whose callers are app threads.
///
/// Every method blocks its caller and is refused from inside an async
/// runtime, an app host callback included ([`ensure_app_thread`]). Calls
/// may come from several app threads at once.
///
/// [`Self::close`] stops serving in order, then drops the runtime; call it
/// from an app thread. Dropped unclosed, it closes the same way on the
/// dropping thread, or, when that thread is inside a runtime, on a thread
/// of its own, so nothing blocks inside a runtime.
pub struct BlockingEngine<A: AppHost + Clone + 'static> {
    running: RwLock<Option<Running<A>>>,
    path: std::path::PathBuf,
    dimensions: usize,
}

impl<A: AppHost + Clone + 'static> BlockingEngine<A> {
    /// Starts an engine as [`EmbeddedEngine::start`] does, on a runtime of
    /// its own.
    pub fn start(app: A, config: ServeConfig, limits: HostLimits) -> anyhow::Result<Self> {
        ensure_app_thread()?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("oneiron-engine")
            .build()
            .context("the embedded engine's runtime did not start")?;
        let engine = runtime.block_on(EmbeddedEngine::start(app, config, limits))?;
        Ok(Self {
            path: engine.path().to_path_buf(),
            dimensions: engine.config().dimensions,
            running: RwLock::new(Some(Running { engine, runtime })),
        })
    }

    /// The vault's directory.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The embedding width the vault was opened with.
    pub fn dimensions(&self) -> usize {
        self.dimensions
    }

    /// The open vault, to share; refused once closed.
    pub fn vault(&self) -> anyhow::Result<Arc<oneiron::Vault>> {
        self.with_running(|running| Ok(Arc::clone(running.engine.vault())))
    }

    /// [`EmbeddedEngine::request`].
    pub fn request(&self, request: EmbeddedRequest) -> anyhow::Result<EmbeddedReply> {
        self.with_running(|running| running.runtime.block_on(running.engine.request(request)))
    }

    /// [`EmbeddedEngine::wake`].
    pub fn wake(&self) -> anyhow::Result<()> {
        self.with_running(|running| running.runtime.block_on(running.engine.wake()))
    }

    /// [`EmbeddedEngine::stop`].
    pub fn stop(&self) -> anyhow::Result<()> {
        self.with_running(|running| running.runtime.block_on(running.engine.stop()))
    }

    /// Stops serving in order and releases the runtime and the engine's
    /// share of the vault. Later calls are refused; closing again does
    /// nothing.
    pub fn close(&self) -> anyhow::Result<()> {
        ensure_app_thread()?;
        let running = self
            .running
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        running.map_or(Ok(()), Running::close)
    }

    fn with_running<T>(
        &self,
        call: impl FnOnce(&Running<A>) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        ensure_app_thread()?;
        let running = self.running.read().unwrap_or_else(PoisonError::into_inner);
        let running = running
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("the embedded engine is closed"))?;
        call(running)
    }
}

impl<A: AppHost + Clone + 'static> Drop for BlockingEngine<A> {
    fn drop(&mut self) {
        let Some(running) = self
            .running
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        else {
            return;
        };
        if Handle::try_current().is_err() {
            close_logged(running);
            return;
        }
        // Dropped inside a runtime, where nothing may block: the ordered
        // stop finishes on a thread of its own.
        let (hand_over, handed) = std::sync::mpsc::channel::<Running<A>>();
        let closer = std::thread::Builder::new()
            .name("oneiron-engine-close".to_owned())
            .spawn(move || {
                if let Ok(running) = handed.recv() {
                    close_logged(running);
                }
            });
        match closer {
            Ok(_) => {
                let _ = hand_over.send(running);
            }
            Err(error) => {
                tracing::warn!(%error, "the embedded engine could not stop in order; stopping it at once");
                let Running { engine, runtime } = running;
                drop(engine);
                runtime.shutdown_background();
            }
        }
    }
}

fn close_logged<A: AppHost + Clone + 'static>(running: Running<A>) {
    if let Err(error) = running.close() {
        tracing::warn!(%error, "the embedded engine did not stop cleanly");
    }
}
