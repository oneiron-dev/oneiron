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
//! without one the server advertises no artifact origin.
//!
//! The app's keychain answers the secrets the config does not name. Its
//! timer is armed for the Dreamer's next wake and wakes the engine back
//! through [`EmbeddedHost::wake_handle`]. [`EmbeddedHost::stop_handle`] stops
//! serving: connections drain, then every worker stops. No process signal is
//! watched here.
//!
//! [`EmbeddedEngine`] is the whole of it for a binding: from a path and the
//! app's host it opens the vault the way `oneiron serve` does
//! ([`open_served_vault`]), serves it, answers one buffered request at a
//! time over a fresh duplex stream, and stops and restarts serving over the
//! same open vault. [`BlockingEngine`] runs one on a runtime of its own for
//! a binding whose callers are app threads.

mod engine;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use hyper::body::Incoming;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use oneiron_vault_contract::host::{Host, HostLimits};
use oneiron_vault_contract::host_adapters::{AppHost, EmbeddedHost};
use tokio::io::DuplexStream;
use tokio::sync::{mpsc, watch};

pub use self::engine::{
    BlockingEngine, EmbeddedEngine, EmbeddedReply, EmbeddedRequest, embedded_serve_config,
    ensure_app_thread, host_limits, unix_millis,
};
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
/// returns once connections have drained and every worker has stopped. The
/// app's timer stays armed for the next wake.
///
/// Run it on a multi-thread Tokio runtime, outside a `LocalSet`, as
/// [`crate::build_app`] says.
pub async fn serve_embedded<A: AppHost>(
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
    serve_prepared(host, vault, config, artifacts, owner_host).await
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
    let mesh_server = Arc::clone(&started.server);
    let app = crate::build_app_for_position(started.server, DeploymentPosition::Embedded)
        .layer(cors_layer);
    let header_read_timeout = config.limits.connections().header_read_timeout;
    // The paired-machine mesh listener (OF-535): off unless the host names
    // its bind address.
    let mesh = crate::handler::mesh::start(
        mesh_server,
        &crate::handler::mesh::MeshConfig::from_env()?,
        &app,
        config.limits.connections(),
    )
    .await?;
    host.ready()?;
    let (stopping, mut stopped) = (started.stopping, started.stopped);
    let api = serve_channel(connections, app, header_read_timeout, stopped.clone());
    let artifact_app = started.artifact_app;
    let artifact_stop = stopped.clone();
    let artifact = async move {
        if let Some(artifacts) = artifacts {
            serve_channel(artifacts, artifact_app, header_read_timeout, artifact_stop).await;
        }
    };
    let stop = host.stop_handle();
    let serving = async {
        let stop_on_app = async {
            stop.notified().await;
            tracing::info!("the app asked the engine to stop; finishing in-flight work");
            let _ = stopping.send(true);
        };
        tokio::join!(stop_on_app, api, artifact);
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
    if let Some(mesh) = mesh {
        mesh.stop().await;
    }
    started.workers.shutdown(|| host.on_stop()).await
}

/// The owner host serve gives its server: a rehearsal restores into a plain
/// scratch vault, so its config carries no page seal.
fn owner_host(config: &ServeConfig) -> crate::owner::schedule::OwnerHost {
    let mut rehearsal_config = config.vault_config();
    rehearsal_config.dict_search_paths =
        crate::commands::resolve_dict_search_paths(&config.dict_search_paths).paths;
    rehearsal_config.page_seal = None;
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

/// Serves `app` over each stream the app hands in, as the mesh serves its
/// streams: one HTTP/1.1 connection per stream, upgrades included. Once
/// `stopped` turns it takes no more streams, ends each open connection
/// gracefully and returns when all have closed.
async fn serve_channel(
    mut connections: mpsc::Receiver<DuplexStream>,
    app: Router,
    header_read_timeout: Duration,
    mut stopped: watch::Receiver<bool>,
) {
    let (open, open_watch) = watch::channel(());
    loop {
        let stream = tokio::select! {
            stream = connections.recv() => match stream {
                Some(stream) => stream,
                None => break,
            },
            _ = stopped.wait_for(|stop| *stop) => break,
        };
        let routes = TowerToHyperService::new(app.clone());
        let service = hyper::service::service_fn(move |request: hyper::Request<Incoming>| {
            let mut request = request.map(Body::new);
            request
                .extensions_mut()
                .insert(ConnectInfo(IN_PROCESS_PEER));
            hyper::service::Service::call(&routes, request)
        });
        let mut stop = stopped.clone();
        let held = open_watch.clone();
        tokio::spawn(async move {
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder
                .timer(TokioTimer::new())
                .header_read_timeout(header_read_timeout);
            let mut connection = pin!(
                builder
                    .serve_connection(TokioIo::new(stream), service)
                    .with_upgrades()
            );
            // A stream the app closed is the app's business, not an error of
            // this server's.
            let stopping = tokio::select! {
                _ = connection.as_mut() => false,
                _ = stop.wait_for(|stopping| *stopping) => true,
            };
            if stopping {
                connection.as_mut().graceful_shutdown();
                let _ = connection.as_mut().await;
            }
            drop(held);
        });
    }
    drop(connections);
    drop(open_watch);
    open.closed().await;
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
