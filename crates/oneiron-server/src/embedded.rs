//! The engine inside an app's own process (OF-237): [`serve_embedded`]
//! serves a vault the app already opened over the [`EmbeddedHost`] channel,
//! with the server and the workers `oneiron serve` starts.
//!
//! The channel is full duplex: each connection the app hands in through
//! [`EmbeddedHost::connector`] is one [`DuplexStream`] carrying HTTP/1.1,
//! upgrades included, so `/ws` works as it does on a socket. That is a
//! transport choice: a request-and-reply envelope could not carry an
//! upgrade. The app is this process, so every caller is on this device.
//!
//! The artifact app (`/a/`) keeps an origin of its own and never rides the
//! API channel: a second channel serves it when the app passes one, and
//! without one the server advertises no artifact origin. [`EmbeddedEngine`]
//! always passes one, which its artifact requests and connections reach.
//!
//! The app's keychain answers the secrets the config does not name. Its
//! timer is armed for the Dreamer's next wake and wakes the engine back
//! through [`EmbeddedHost::wake_handle`]. [`EmbeddedHost::stop_handle`] stops
//! serving: connections drain and the mesh takes no more, every socket
//! upgraded on either ends once the calls it admitted have, then every worker
//! stops. No process signal is watched here.
//!
//! [`EmbeddedEngine`] is the whole of it for a binding: from a path and the
//! app's host it opens the vault the way `oneiron serve` does
//! ([`open_served_vault`]), serves it, answers one buffered request at a
//! time over a fresh duplex stream, hands the app a connection of its own
//! for `/ws` and streamed replies ([`EmbeddedConnection`]), streams one
//! request's reply ([`EmbeddedEngine::request_streamed`]), and stops and
//! restarts serving over the same open vault. [`BlockingEngine`] runs one on
//! a runtime of its own for a binding whose callers are app threads, and
//! [`ProcessHost`] is the host of a binding whose app is a plain process.
//! Each failure names its cause ([`EngineErrorKind`]), which every binding
//! raises as a stable code.

mod blocking;
mod engine;
mod failure;
mod process_host;
mod runtime;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::ConnectInfo;
use axum::http::Extensions;
use hyper::body::Incoming;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use oneiron_vault_contract::host::{Host, HostLimits};
use oneiron_vault_contract::host_adapters::{AppHost, EmbeddedHost};
use tokio::io::DuplexStream;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;

pub use self::blocking::{BlockingBody, BlockingConnection, BlockingEngine, BlockingReply};
pub use self::engine::{
    ENGINE_RECEIVE_CHUNK_BYTES, EmbeddedBody, EmbeddedConnection, EmbeddedEngine, EmbeddedReply,
    EmbeddedReplyStream, EmbeddedRequest, embedded_serve_config, ensure_app_thread, host_limits,
    unix_millis,
};
pub use self::failure::{EngineErrorKind, EngineFailure, engine_error_kind, engine_memory_error};
pub use self::process_host::ProcessHost;
pub use crate::commands::{OpenedServedVault, open_served_vault};
use crate::config::ServeConfig;
use crate::web_client::DeploymentPosition;

/// The peer every in-process request carries. The app is this process, so
/// its callers are on this device (DEC-0005), as a loopback peer is.
const IN_PROCESS_PEER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

/// The share of the host's memory grant that a memory bound the server sizes
/// from the machine takes in its place: an eighth, as those bounds take of the
/// machine's memory.
const HOST_MEMORY_SHARE: u64 = 8;
/// The share of it one pushed blob's scan takes: a sixty-fourth, as of the
/// machine's.
const HOST_SCAN_BLOB_SHARE: u64 = 64;

/// Why an embedded engine never serves a relay host's config.
const RELAY_REFUSAL: &str =
    "a relay host never opens a vault; use `oneiron host relay --config <room.json>`";

/// Serves `vault` over `host`'s channel until the app stops it.
///
/// `vault` is the app's one opened vault, opened with `Vault::open_owned`
/// under `config`. The server shares it and never opens the path again; an
/// SDK handle shares it through `OneironClient::attach`. `artifacts` is the
/// artifact app's own channel, or `None` to serve no artifact origin.
///
/// Ready is reported once every worker runs. When the app backgrounds it
/// fires `host.stop_handle()` with `notify_one` and awaits this, which
/// returns once connections have drained, every socket upgraded on them or on
/// the mesh has ended with the calls it admitted, and every worker has
/// stopped. The app's timer stays armed for the next wake.
///
/// Run it on a multi-thread Tokio runtime, outside a `LocalSet`, as
/// [`crate::build_app`] says. It serves on that runtime, unless `host`'s
/// limits grant a bounded CPU share: it then serves on a runtime of its own,
/// on a thread of its own, whose worker threads that share caps (FIX 2661),
/// and dropping this future before it returns stops serving in order.
pub async fn serve_embedded<A: AppHost + 'static>(
    host: EmbeddedHost<A, DuplexStream>,
    vault: Arc<oneiron::Vault>,
    config: ServeConfig,
    artifacts: Option<mpsc::Receiver<DuplexStream>>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        config.privacy_posture != oneiron::HostingPrivacyPosture::Relay,
        RELAY_REFUSAL
    );
    let owner_host = owner_host(&config);
    let Some(workers) = runtime::worker_cap(host.limits()) else {
        return serve_prepared(host, vault, config, artifacts, owner_host).await;
    };
    let _stop = runtime::StopOnDrop(host.stop_handle());
    let done = runtime::spawn_serving(Some(workers), move || {
        serve_prepared(host, vault, config, artifacts, owner_host)
    })?;
    runtime::served(done).await
}

/// [`serve_embedded`]'s body, given the owner host the vault's opener
/// already built, so its rehearsal config is resolved once. `config` is
/// not a relay's: each caller refuses one first.
async fn serve_prepared<A: AppHost>(
    mut host: EmbeddedHost<A, DuplexStream>,
    vault: Arc<oneiron::Vault>,
    mut config: ServeConfig,
    artifacts: Option<mpsc::Receiver<DuplexStream>>,
    owner_host: crate::owner::schedule::OwnerHost,
) -> anyhow::Result<()> {
    // The app's keychain, when config and environment name no secret.
    if config.auth_secret.is_none()
        && let Ok(secret) = host.secret("auth_secret")
    {
        config.auth_secret = Some(String::from_utf8(secret.to_vec())?);
    }
    apply_host_limits(&mut config, host.limits());
    // The app's channel, taken once, before any worker starts.
    let connections = host.listener()?;
    let server_config = config.sync_server_config();
    if let Err(error) =
        crate::commands::sign_root_project(&vault, server_config.auth_secret.as_deref())
    {
        tracing::warn!(%error, "the root project was not signed; it stays unsigned until the next start");
    }
    crate::owner::house::bind_house_leader_at_start(&vault, server_config.auth_secret.as_deref());
    if server_config.auth_secret.is_none() && !server_config.allow_unauthenticated {
        tracing::warn!(
            "embedded server started with no auth_secret and allow_unauthenticated=false; refusing all requests"
        );
    }
    let cors_layer = crate::commands::build_cors_layer(&server_config)?;
    let (sync_server, gpu_poller) =
        crate::commands::build_server(vault, &config, server_config, owner_host).await?;
    let sync_server = if artifacts.is_some() {
        sync_server.with_artifact_socket()
    } else {
        sync_server
    };
    let started = crate::commands::start_desktop_workers(
        sync_server,
        &config,
        gpu_poller,
        crate::server::admit_every_pass,
    )
    .await?;
    let next_wake = started.workers.ai().next_wake();
    let ai = started.workers.ai().handle();
    let (stopping, mut stopped) = (started.stopping, started.stopped);
    // Each socket upgraded on the app's channels or on the mesh holds a place
    // in this drain from before its upgrade registers until it ends, which it
    // does on the stop once the calls it admitted have finished. It is made
    // before the router and the mesh, so every request either serves carries
    // it.
    let upgrades = UpgradeLifetime::new(stopped.clone());
    let mesh_server = Arc::clone(&started.server);
    let app = crate::build_app_for_position(started.server, DeploymentPosition::Embedded)
        .layer(cors_layer);
    // Each channel's connections meet the socket's header deadline and body
    // idle limit, and its requests the router's own body floors; a trusted
    // in-process stream takes no connection permit or stranger share
    // (FIX 2663).
    let timeouts = ChannelTimeouts::of(&config);
    // The paired-machine mesh listener (OF-535): off unless the host names
    // its bind address. Its requests carry the drain as the channel's do.
    let mesh_app = app.clone().layer(axum::Extension(upgrades.clone()));
    let mesh = crate::handler::mesh::start(
        Arc::clone(&mesh_server),
        &crate::handler::mesh::MeshConfig::from_env()?,
        &mesh_app,
        config.limits.connections(),
    )
    .await?;
    // A machine that is not the elected home dials its home, on that mesh
    // when the home has a paired address there.
    let device_sync =
        crate::device_sync::DeviceSyncHost::start(&mesh_server, &config, mesh.as_ref()).await;
    host.ready()?;
    // Each channel's HTTP connections are tasks of its set here.
    let (mut api_http, mut artifact_http) = (JoinSet::new(), JoinSet::new());
    let api = serve_channel(connections, app, timeouts, upgrades.clone(), &mut api_http);
    let artifact_app = started.artifact_app;
    let artifact_upgrades = upgrades.clone();
    let artifact_connections = &mut artifact_http;
    let artifact = async move {
        if let Some(artifacts) = artifacts {
            serve_channel(
                artifacts,
                artifact_app,
                timeouts,
                artifact_upgrades,
                artifact_connections,
            )
            .await;
        }
    };
    let stop = host.stop_handle();
    let mut mesh_stopped = stopped.clone();
    let serving = async {
        let stop_on_app = async {
            stop.notified().await;
            tracing::info!("the app asked the engine to stop; finishing in-flight work");
            let _ = stopping.send(true);
        };
        // On the stop the mesh takes no more connections or streams, and its
        // sync streams end as the channels' connections do, in the same grace.
        let mesh_closing = async {
            if let Some(mesh) = &mesh {
                stop_turned(&mut mesh_stopped).await;
                mesh.close_streams().await;
            }
        };
        tokio::join!(stop_on_app, api, artifact, mesh_closing);
    };
    tokio::select! {
        () = serving => {}
        () = async {
            let _ = stopped.wait_for(|stop| *stop).await;
            tokio::time::sleep(crate::commands::DRAIN_GRACE).await;
        } => {
            tracing::warn!("connections still open after the drain grace; stopping anyway");
        }
        () = forward_wakes(&mut host, next_wake, &ai) => {}
    }
    // Every connection closed, or the grace ran out and the race dropped the
    // channels with some still open. Those, and the mesh's sync streams, are
    // aborted and reaped here, so an upgrade one never finished releases its
    // place in the drain. Each upgraded socket saw the stop: it stops reading
    // at its next wait, closes, and ends once every call it admitted has.
    // Its drain is awaited here, outside the grace race: no worker stops
    // under a socket or a call one admitted.
    api_http.shutdown().await;
    artifact_http.shutdown().await;
    if let Some(mesh) = &mesh {
        mesh.end_streams().await;
    }
    upgrades.drained().await;
    if let Some(device_sync) = device_sync {
        device_sync.stop().await;
    }
    if let Some(mesh) = mesh {
        mesh.stop().await;
    }
    // Every public live voice session ends through its own teardown, its
    // journal finished, and none starts after, as plain serve ends them.
    mesh_server.live_voice.stop_all().await;
    started.workers.shutdown(|| host.on_stop()).await
}

/// The owner host serve gives its server: a rehearsal restores into a plain
/// scratch vault, so its config carries no page seal.
fn owner_host(config: &ServeConfig) -> crate::owner::schedule::OwnerHost {
    let mut rehearsal_config = config.base_vault_config();
    rehearsal_config.dict_search_paths =
        crate::commands::resolve_dict_search_paths(&config.dict_search_paths).paths;
    crate::owner::schedule::OwnerHost::from_config(config, rehearsal_config)
}

/// The host's memory grant stands in for the machine's memory: each memory
/// bound sized from the machine takes the same share of the grant when that
/// is smaller. An unbounded grant changes nothing.
fn apply_host_limits(config: &mut ServeConfig, host: HostLimits) {
    if host.memory_bytes == HostLimits::unbounded().memory_bytes {
        return;
    }
    let share = host.memory_bytes / HOST_MEMORY_SHARE;
    let limits = &mut config.limits;
    limits.lfs_memory_bytes = limits.lfs_memory_bytes.min(share);
    limits.retained_memory_bytes = limits.retained_memory_bytes.min(share);
    limits.git_scan_blob_bytes = limits
        .git_scan_blob_bytes
        .min(host.memory_bytes / HOST_SCAN_BLOB_SHARE);
}

/// What a socket upgraded on an embedded engine's channel or mesh lives under
/// (OF-237): the engine's stop watch, and the drain serving awaits before any
/// worker stops. [`serve_channel`] puts it on every request it serves, and the
/// mesh's router carries it as an extension; a server that is not embedded
/// puts none, and its sockets run as they always have.
#[derive(Clone)]
struct UpgradeLifetime {
    stopped: watch::Receiver<bool>,
    /// Each receiver subscribed to it is one upgrade's place in the drain.
    drain: watch::Sender<()>,
}

impl UpgradeLifetime {
    fn new(stopped: watch::Receiver<bool>) -> Self {
        Self {
            stopped,
            drain: watch::Sender::new(()),
        }
    }

    /// Returns once every place taken in the drain has been released.
    async fn drained(&self) {
        self.drain.closed().await;
    }
}

/// One upgrade's place in its embedded engine's drain, and that engine's stop
/// watch. Dropped, with the callback that owns it or with an upgrade that
/// never completed, it releases the place.
pub(crate) struct UpgradeHold {
    stopped: watch::Receiver<bool>,
    place: watch::Receiver<()>,
}

impl UpgradeHold {
    /// The hold an embedded engine's channel asks of an upgrade on the
    /// request whose `extensions` these are, taken before the upgrade
    /// registers, so the drain waits for it from the start. `None` for a
    /// request no embedded channel carried.
    pub(crate) fn take(extensions: &Extensions) -> Option<Self> {
        extensions.get::<UpgradeLifetime>().map(|lifetime| Self {
            stopped: lifetime.stopped.clone(),
            place: lifetime.drain.subscribe(),
        })
    }

    /// Runs `socket`, an upgrade's whole callback, under `hold`, handing it
    /// the engine's stop, which the callback answers itself: it stops reading
    /// at its next wait, closes its transport and waits for every call it
    /// admitted. Its place is released only once it has returned, so no call
    /// is cut off and no worker stops under one. Without a hold the stop never
    /// turns.
    pub(crate) async fn run<F: Future<Output = ()>>(
        hold: Option<Self>,
        socket: impl FnOnce(UpgradeStop) -> F,
    ) {
        let (stop, place) = match hold {
            Some(Self { stopped, place }) => (UpgradeStop(Some(stopped)), Some(place)),
            None => (UpgradeStop(None), None),
        };
        socket(stop).await;
        drop(place);
    }
}

/// An embedded engine's stop, as the socket [`UpgradeHold::run`] runs sees it
/// (OF-237). A socket no embedded engine carried has one that never turns.
#[derive(Clone)]
pub(crate) struct UpgradeStop(Option<watch::Receiver<bool>>);

impl UpgradeStop {
    /// Returns once the engine stops, and at once from then on; never for a
    /// socket outside an embedded engine.
    pub(crate) async fn turned(&mut self) {
        match &mut self.0 {
            Some(stopped) => stop_turned(stopped).await,
            None => std::future::pending().await,
        }
    }

    /// `wait` until the engine stops: `None` when the stop came first and
    /// `wait` was dropped where it waited. Only for a wait on the peer or on a
    /// turn, never for a call the socket admitted.
    pub(crate) async fn until<T>(&mut self, wait: impl Future<Output = T>) -> Option<T> {
        tokio::select! {
            biased;
            () = self.turned() => None,
            done = wait => Some(done),
        }
    }
}

/// Returns once `stopped` turns, or once its sender is gone, which is a
/// server that has stopped.
async fn stop_turned(stopped: &mut watch::Receiver<bool>) {
    let _ = stopped.wait_for(|stop| *stop).await;
}

/// The deadlines an embedded channel's connections meet: a socket's own.
#[derive(Clone, Copy)]
struct ChannelTimeouts {
    /// How long a request's headers may take to arrive.
    header_read: Duration,
    /// How long a route may wait for the next piece of a request body: a
    /// body that sends nothing for this long is ended, one that keeps
    /// arriving, however slowly, never is (FIX 2663). The `[limits]` row
    /// `body_idle_timeout_ms`, which TCP and mesh requests meet too.
    body_idle: Duration,
}

impl ChannelTimeouts {
    fn of(config: &ServeConfig) -> Self {
        let limits = config.limits.connections();
        Self {
            header_read: limits.header_read_timeout,
            body_idle: limits.body_idle_timeout,
        }
    }
}

/// Serves `app` over each stream the app hands in, as the mesh serves its
/// streams: one HTTP/1.1 connection per stream, upgrades included, each a
/// task of `http`, under `timeouts`. Every request carries `upgrades`, so a
/// socket it upgrades to ends on the stop and is waited for before any
/// worker stops. Once the stop watch turns it takes no more streams, ends
/// each open connection gracefully and returns when all have closed.
/// Dropped before then, at the drain grace, it leaves the open ones in
/// `http` for its caller to abort.
async fn serve_channel(
    mut connections: mpsc::Receiver<DuplexStream>,
    app: Router,
    timeouts: ChannelTimeouts,
    upgrades: UpgradeLifetime,
    http: &mut JoinSet<()>,
) {
    let mut stopped = upgrades.stopped.clone();
    loop {
        let stream = tokio::select! {
            stream = connections.recv() => match stream {
                Some(stream) => stream,
                None => break,
            },
            () = stop_turned(&mut stopped) => break,
            // A connection is reaped as it ends, so the set holds open ones.
            Some(_) = http.join_next(), if !http.is_empty() => continue,
        };
        let routes = TowerToHyperService::new(app.clone());
        let lifetime = upgrades.clone();
        let service = hyper::service::service_fn(move |request: hyper::Request<Incoming>| {
            let mut request =
                request.map(|body| crate::http_listener::idle_body(body, timeouts.body_idle));
            let extensions = request.extensions_mut();
            extensions.insert(ConnectInfo(IN_PROCESS_PEER));
            extensions.insert(lifetime.clone());
            hyper::service::Service::call(&routes, request)
        });
        let mut stop = stopped.clone();
        http.spawn(async move {
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder
                .timer(TokioTimer::new())
                .header_read_timeout(timeouts.header_read);
            let mut connection = pin!(
                builder
                    .serve_connection(TokioIo::new(stream), service)
                    .with_upgrades()
            );
            // A stream the app closed is the app's business, not an error of
            // this server's.
            let stopping = tokio::select! {
                _ = connection.as_mut() => false,
                () = stop_turned(&mut stop) => true,
            };
            if stopping {
                connection.as_mut().graceful_shutdown();
                let _ = connection.as_mut().await;
            }
        });
    }
    drop(connections);
    while http.join_next().await.is_some() {}
}

/// Arms the app's timer for the Dreamer's next wake as it changes, and hands
/// each wake of the app's (its timer, or a push) to the Dreamer as a hint, on
/// which each of its lanes re-reads what is due by the wall clock. It records
/// the driver's own timer decisions and schedules nothing of its own. It runs
/// until serving stops.
async fn forward_wakes<A: AppHost>(
    host: &mut EmbeddedHost<A, DuplexStream>,
    mut next_wake: Option<watch::Receiver<Option<u64>>>,
    ai: &crate::ai_host::AiHandle,
) {
    let woken = host.wake_handle();
    loop {
        let at = next_wake
            .as_mut()
            .and_then(|next| *next.borrow_and_update())
            .map(|ms| UNIX_EPOCH + Duration::from_millis(ms));
        if at.is_some_and(|at| at <= SystemTime::now()) {
            // Due now: the Dreamer is running it and re-arms after. A timer
            // armed in the past would only fire at once, so none is armed.
            tokio::select! {
                () = woken.notified() => ai.attempt_queued(),
                () = wake_moved(&mut next_wake) => {}
            }
            continue;
        }
        let woke = tokio::select! {
            woke = host.idle(at) => Some(woke),
            () = wake_moved(&mut next_wake) => None,
        };
        match woke {
            // A fired timer and an app wake look alike here; either way the
            // Dreamer re-reads its lanes once.
            Some(Ok(())) => ai.attempt_queued(),
            Some(Err(error)) => {
                tracing::warn!(%error, "the app's wake timer was not armed");
                wake_moved(&mut next_wake).await;
            }
            None => {}
        }
    }
}

/// The next change of the Dreamer's next wake. Never, once there is none to
/// follow.
async fn wake_moved(next_wake: &mut Option<watch::Receiver<Option<u64>>>) {
    match next_wake {
        Some(receiver) => {
            if receiver.changed().await.is_err() {
                *next_wake = None;
            }
        }
        None => std::future::pending().await,
    }
}
