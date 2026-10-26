//! The unmanaged serve path: open the vault, build the server and its
//! workers, serve until a stop signal, then stop every worker cleanly.

use std::net::SocketAddr;
use std::sync::Arc;

use super::{build_cors_layer, should_warn_public_bind_without_auth, weak_auth_secret_warning};
use crate::build_app;
use crate::build_artifact_app;
use crate::config::ServeConfig;
use crate::owner::backup::CustodyAnchorCredentials;
use crate::server::SyncServer;

#[cfg(unix)]
use super::{history_import, local_servers};

mod hooks;
mod page_seal;
mod stop;
mod workers;
pub(crate) use self::hooks::hook_sandbox;
#[cfg(feature = "code-sandbox-wasmtime")]
pub(crate) use self::hooks::spawn_fact_hooks;
pub(crate) use self::page_seal::open_served_vault_anchored;
pub use self::page_seal::{OpenedServedVault, open_served_vault};
pub(crate) use self::workers::start_desktop_workers;

/// How long open connections get to finish after a stop is requested.
pub(crate) const DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

/// The plist's `Sockets` key and the keychain service launchd's daemon reads
/// its secrets from, as `deploy/launchd/com.oneiron.server.plist` names them.
const LAUNCHD_SOCKET: &str = "Listeners";
const KEYCHAIN_SERVICE: &str = "com.oneiron.server";

/// [`serve_anchored`] handed no custody anchor credential.
#[cfg(test)]
pub(super) async fn serve_with_config(
    config: ServeConfig,
    files: Option<super::ConfigFiles>,
) -> anyhow::Result<()> {
    serve_anchored(config, files, None).await
}

/// `files` are the files `config` was read from, which the server's runtime
/// file names for a client that queues imports to it. `anchor` is the custody
/// anchor door's owner credential the operator handed on its pipe.
pub(super) async fn serve_anchored(
    mut config: ServeConfig,
    files: Option<super::ConfigFiles>,
    anchor: Option<Arc<CustodyAnchorCredentials>>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        config.privacy_posture != oneiron::HostingPrivacyPosture::Relay,
        "a relay host never opens a vault; use `oneiron host relay --config <room.json>`"
    );
    use oneiron_vault_contract::host::Host;
    use oneiron_vault_contract::host_adapters::{ActivatedListener, AwakePolicy, DesktopHost};

    tracing::info!(
        vault_path = %config.vault_path.display(),
        dimensions = config.dimensions,
        "starting oneiron sync server"
    );
    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    // systemd or launchd may have bound the socket and hold the secrets;
    // otherwise this binds `addr` itself. Read once, at process entry.
    let mut host = DesktopHost::detect(addr, LAUNCHD_SOCKET, KEYCHAIN_SERVICE)?;
    tracing::info!(adapter = host.adapter(), "host adapter");
    // The service manager's credential store, when config and environment
    // name no secret.
    if config.auth_secret.is_none()
        && let Ok(secret) = host.secret("auth_secret")
    {
        config.auth_secret = Some(String::from_utf8(secret.to_vec())?);
    }
    refuse_unauthenticated_public_bind(&config, addr)?;

    let OpenedServedVault { vault, owner_host } =
        open_served_vault_anchored(&mut host, &config, anchor)?;

    let server_config = config.sync_server_config();
    if let Err(error) = sign_root_project(&vault, server_config.auth_secret.as_deref()) {
        tracing::warn!(%error, "the root project was not signed; it stays unsigned until the next start");
    }
    crate::owner::house::bind_house_leader_at_start(&vault, server_config.auth_secret.as_deref());
    match server_config.auth_secret.as_deref() {
        None if !server_config.allow_unauthenticated => {
            tracing::warn!(
                "server started with no auth_secret and allow_unauthenticated=false; refusing all requests; set ONEIRON_AUTH_SECRET or pass --insecure-allow-unauthenticated for local dev"
            );
            if should_warn_public_bind_without_auth(
                server_config.auth_secret.as_deref(),
                server_config.allow_unauthenticated,
                &config.host,
            ) {
                tracing::warn!(
                    host = %config.host,
                    "server listener is network-exposed while refusing unauthenticated requests"
                );
            }
        }
        // A nudge, not a wall: short dev secrets keep working.
        Some(secret) => {
            if let Some(warning) = weak_auth_secret_warning(secret) {
                tracing::warn!("{warning}");
            }
        }
        None => {}
    }
    let cors_layer = build_cors_layer(&server_config)?;

    // Built before the listener binds: a reachable endpoint that serves the
    // wrong embedding space must stop serve rather than fill a vault from two
    // spaces. The local provider downloads nothing here — that is the worker's.
    let (sync_server, gpu_poller) = build_server(vault, &config, server_config, owner_host).await?;
    // The host's socket: adopted from the service manager, or host:port
    // bound here. Bound before any worker starts, so a refused bind leaves
    // nothing running. An adopted socket is judged by where it listens.
    let ActivatedListener::Tcp(listener) = host.listener()? else {
        anyhow::bail!("serve listens on TCP; activate it with ListenStream=<host>:<port>");
    };
    refuse_unauthenticated_public_bind(&config, listener.local_addr()?)?;
    listener.set_nonblocking(true)?;
    let listener = tokio::net::TcpListener::from_std(listener)?;
    #[cfg(unix)]
    let bound = listener.local_addr()?;
    // `/a/` on an origin of its own, so a code bundle's scripts never run on
    // the API's: same host, its own port. Bound before any worker starts too.
    let artifact_bind = SocketAddr::new(addr.ip(), config.artifact_port);
    let artifact_listener = tokio::net::TcpListener::bind(artifact_bind)
        .await
        .map_err(|error| anyhow::anyhow!("artifact listener bind {artifact_bind}: {error}"))?;
    let artifact_addr = artifact_listener.local_addr()?;
    let sync_server = sync_server.with_artifact_listener(artifact_addr.port());
    tracing::info!(%addr, artifacts = %artifact_addr, "listening");
    // Borrowed uniquely, so the closure is `Send` whenever the host is.
    let awake_host = &mut host;
    let started = start_desktop_workers(
        sync_server,
        &config,
        gpu_poller,
        move || -> crate::server::HousekeepingAdmission {
            // A wake pass keeps a plugged-in laptop awake until it ends; on battery
            // normal idle sleep holds (ruled 2026-10-08).
            let awake = awake_host.keep_awake(AwakePolicy::default());
            // It follows the power source while held; a host whose changes
            // cannot be observed says so once (FIX 9547).
            awake.on_unobserved(|| {
                tracing::warn!(
                    reason = "power_source_unobserved",
                    "power-source changes are not observed; a wake assertion follows the source sampled as its holds began"
                );
            });
            // A live model run holds the same assertion through each admitted call,
            // not only a wake pass (Docs Q18).
            oneiron_vault_contract::host_adapters::hold_awake_for_runs({
                let awake = awake.clone();
                move || Box::new(awake.hold()) as Box<dyn Send>
            });
            let admit = crate::server::admit_every_pass();
            Arc::new(move || {
                let pass = admit()?;
                Some(Box::new((pass, awake.hold())) as Box<dyn Send>)
            })
        },
        // Tagging stops with serve and settles every call it made (FIX 7303).
        true,
    )
    .await?;
    let sync_server = started.server;
    let artifact_app = started.artifact_app;
    let questions = started.questions;
    #[cfg(unix)]
    let vault_id = started.vault_id;
    let (stopping, mut stopped) = (started.stopping, started.stopped);
    let workers = started.workers;
    let mesh_server = Arc::clone(&sync_server);
    // Each socket upgraded on the API listener or the mesh sees the stop, and
    // the stop waits for it and the calls it admitted (FIX 4757).
    let (app, upgrades) = crate::embedded::upgrade_lifetime(
        build_app(sync_server).layer(cors_layer),
        stopped.clone(),
    );
    // A startup error from here on stops what started and joins every worker
    // before it is returned (FIX 7386).
    let (mut mesh, mut device_sync) = (None, None);
    let startup = async {
        // The paired-machine mesh listener (OF-535): off unless the host
        // names its bind address.
        mesh = crate::handler::mesh::start(
            Arc::clone(&mesh_server),
            &crate::handler::mesh::MeshConfig::from_env()?,
            &app,
            config.limits.connections(),
        )
        .await?;
        // A machine that is not the elected home dials its home, on that
        // mesh when the home has a paired address there.
        device_sync =
            crate::device_sync::DeviceSyncHost::start(&mesh_server, &config, mesh.as_ref()).await;
        host.ready()?;
        anyhow::Ok(())
    }
    .await;
    if let Err(error) = startup {
        let _ = stopping.send(true);
        stop::stop_serving(&mesh_server, mesh, device_sync, upgrades).await;
        if let Err(cleanup) = workers.shutdown(|| host.on_stop()).await {
            tracing::warn!(error = %cleanup, "the workers of a failed start did not stop cleanly");
        }
        return Err(error);
    }
    // Ready and bound: a client on this host can find it now. The file goes
    // when serving stops and this returns; a startup error returned above,
    // before it was written.
    #[cfg(unix)]
    let _registered =
        super::local_servers::register(vault_id, bound, &config.vault_path, files.as_ref());
    #[cfg(not(unix))]
    let _ = files;
    let stop = |mut stopped: tokio::sync::watch::Receiver<bool>| async move {
        let _ = stopped.wait_for(|stop| *stop).await;
    };
    let (api_stop, artifact_stop) = (stop(stopped.clone()), stop(stopped.clone()));
    // Connections are admitted, and their headers timed, before any route
    // runs. Both listeners draw on one pool, so the descriptor floor and each
    // address's unauthenticated share hold for the daemon, not per socket.
    // Past the floor the API listener's sockets may take the pool's owner
    // reserve, which this server judges (FIX 8274).
    let limits = config.limits.connections();
    let pool = crate::http_listener::ConnectionPool::new(&limits, questions);
    let floor_vault = mesh_server.vault();
    floor_vault.lend_host_net_floor(pool.host_net_floor());
    // Foreign guests' proposal spools keep the disk floor uploads keep, on
    // its one shared ledger (FIX 7650).
    floor_vault.lend_proposal_spool(Arc::new(mesh_server.transfers.disk.clone()));
    let owner_judge = Arc::clone(&mesh_server);
    let api = crate::http_listener::serve_api_with_pool(
        listener,
        app,
        &pool,
        limits,
        owner_judge,
        api_stop,
    );
    let artifacts = crate::http_listener::serve_with_pool(
        artifact_listener,
        artifact_app,
        &pool,
        limits,
        artifact_stop,
    );
    let serving = async {
        let stop_on_signal = async {
            stop_requested().await;
            let _ = stopping.send(true);
        };
        tokio::join!(stop_on_signal, api, artifacts);
    };
    tokio::select! {
        () = serving => {}
        () = async {
            let _ = stopped.wait_for(|stop| *stop).await;
            tokio::time::sleep(DRAIN_GRACE).await;
        } => {
            tracing::warn!("connections still open after the drain grace; stopping anyway");
        }
    }
    // Outside the grace: every upgraded socket and the calls it admitted end
    // before the device-sync connection, the mesh and the workers stop.
    stop::stop_serving(&mesh_server, mesh, device_sync, upgrades).await;
    workers.shutdown(|| host.on_stop()).await?;

    Ok(())
}

/// The server over `vault`, with the embedder and tagger slots and the hosts
/// `config` names, and the GPU pool's health poller, already running when
/// `[gpu]` names a pool. Embedded serve builds its server here too.
pub(crate) async fn build_server(
    vault: Arc<oneiron::Vault>,
    config: &ServeConfig,
    mut server_config: crate::config::SyncServerConfig,
    owner_host: crate::owner::schedule::OwnerHost,
) -> anyhow::Result<(SyncServer, Option<tokio::task::JoinHandle<()>>)> {
    // The Linear host's settings: `[linear]`, or with none the
    // `ONEIRON_LINEAR_*` environment read into the same settings, never both.
    server_config.linear =
        crate::config::LinearConfig::or_environment(server_config.linear.take()).await?;
    // The one credential-broker context the `[models]` providers, the System
    // One seat, the embedder and the GPU pods send their vault-secret keys
    // through.
    let broker = crate::models::BrokerContext::for_serve(&vault, config);
    let (embedder, gpu_poller) = build_embedder(&vault, config, broker.as_ref()).await?;
    let tagger = crate::oneironer::build_slot_off_runtime(config.oneironer.clone(), None).await?;

    // Reloads persisted CRDT state (d:root + d:w:* in sync_state) — a fresh
    // boot must not silently discard previously relayed updates/tombstones.
    let sync_server = SyncServer::new(vault, server_config)
        .map_err(|e| anyhow::anyhow!("sync server init failed: {e}"))?
        .with_embedder(embedder)
        .with_tagger(tagger)
        .with_broker(broker)
        .with_owner_host(owner_host)
        .with_browser_guest(
            config
                .browser
                .as_ref()
                .and_then(crate::config::BrowserConfig::guest),
        )
        .with_desktop_guest(
            config
                .desktop
                .as_ref()
                .map(crate::config::DesktopConfig::guest),
        )
        .with_feedback(config.feedback.delivery().map(|delivery| {
            crate::feedback_delivery::FeedbackHost {
                config: delivery,
                bearer: std::env::var("ONEIRON_FEEDBACK_TOKEN")
                    .ok()
                    .filter(|token| !token.is_empty())
                    .map(zeroize::Zeroizing::new),
            }
        }))
        .with_feedback_triage(config.feedback.triage.clone());
    // Its browser readiness starts from the `[browser]` section and its
    // runtime binding, with no supervisor's runtime fact (FIX 7670).
    sync_server
        .browser_readiness()
        .seed(config.browser.as_ref(), None);
    // `[models] extraction_egress = true` is the owner's opt-in for
    // extraction to leave the device (FIX 6621): the raw `/v1/llm` routes
    // and every door that reads the host's predicate admit it, still within
    // the vault's extraction bound. Off, nonlocal extraction stays refused.
    let sync_server = if config
        .models
        .as_ref()
        .is_some_and(|models| models.extraction_egress)
    {
        sync_server.with_extraction_egress(Arc::new(|_: &oneiron::LlmRequest| true))
    } else {
        sync_server
    };
    Ok((sync_server, gpu_poller))
}

/// The embedder slot `config` names, and the GPU pool's health poller,
/// already running when `[gpu]` names a pool. Plain and embedded serve build
/// them through [`build_server`]; managed serve builds them here too. A
/// `key_secret` endpoint, rung or pool sends through `broker`.
pub(crate) async fn build_embedder(
    vault: &Arc<oneiron::Vault>,
    config: &ServeConfig,
    broker: Option<&crate::models::BrokerContext>,
) -> anyhow::Result<(
    Option<crate::embedder::EmbedderSlot>,
    Option<tokio::task::JoinHandle<()>>,
)> {
    // On a blocking thread because the endpoint probe is a blocking HTTP call,
    // which must not run on a runtime worker.
    // The batch lane's rented GPU pods (ARCH-0019 §5), when `[gpu]` names
    // them: the pool polls their health while serve runs, and the endpoint
    // embedder sends its document batches through a lease on one. A vault
    // bound to an account has each pod's answer sealed to that account.
    let gpu = config
        .gpu
        .clone()
        .map(|gpu| crate::runtime::GpuPool::with_broker(gpu, broker))
        .transpose()?;
    let gpu_poller = gpu
        .as_ref()
        .map(crate::runtime::GpuPool::spawn_health_poller);
    // Each pod batch's rows are judged by the vault's world release, held
    // weakly (FIX 9486).
    let release: Arc<dyn crate::embedder::PodRelease> =
        Arc::new(crate::embedder::VaultRelease::new(vault));
    let gpu_route = gpu.map(|pool| (pool, vault.derivation_scope().ok(), release));
    let embedder_config = config.embedder.clone();
    let broker = broker.cloned();
    let embedder = crate::logging::off_runtime("embedder slot task", move || {
        // The server's sink before a host chooses one: the log.
        let receipts = Arc::new(crate::models::ServerReceipts::default());
        let slot = crate::embedder::build_slot_with_broker(
            embedder_config.as_ref(),
            receipts,
            broker.as_ref(),
        )?;
        if let (Some(slot), Some((pool, scope, release))) = (&slot, gpu_route) {
            crate::embedder::route_batches_through(slot, pool, scope, release)?;
        }
        anyhow::Ok(slot)
    })
    .await??;
    Ok((embedder, gpu_poller))
}

/// With no `auth_secret`, `--insecure-allow-unauthenticated` lets a request
/// with no credential act as the owner, so that mode serves only loopback.
/// An empty secret counts as none: it can mint and verify nothing. The
/// address judged is the one this path binds, before the vault opens. A dev
/// server reachable from the LAN sets a secret instead; there is no override.
/// Managed serve never comes here: the supervisor owns its socket.
fn refuse_unauthenticated_public_bind(
    config: &ServeConfig,
    addr: SocketAddr,
) -> anyhow::Result<()> {
    if config.auth_secret.as_deref().is_none_or(str::is_empty)
        && config.allow_unauthenticated
        && !addr.ip().to_canonical().is_loopback()
    {
        anyhow::bail!(
            "unauthenticated mode (--insecure-allow-unauthenticated) serves only a loopback host such as 127.0.0.1 or [::1], and {addr} is reachable from the network; bind loopback or set ONEIRON_AUTH_SECRET"
        );
    }
    Ok(())
}

/// The root project the vault seeds at its first open takes the owner's first
/// signature here, through the host's project.write slip (OF-497). A host
/// with no secret has no issuer, and a relay signs nothing; either leaves the
/// root unsigned. A root that is already signed is left alone.
pub(crate) fn sign_root_project(
    vault: &oneiron::Vault,
    secret: Option<&str>,
) -> anyhow::Result<()> {
    let Some(secret) = secret.filter(|secret| !secret.is_empty()) else {
        return Ok(());
    };
    if vault.privacy_posture() == oneiron::HostingPrivacyPosture::Relay {
        return Ok(());
    }
    let root = vault.root_project()?;
    let unsigned = vault.project_frontier(root)?.is_some_and(|frontier| {
        frontier.disposition == oneiron::workspace_roster::ProjectDisposition::Unsigned
    });
    if !unsigned {
        return Ok(());
    }
    let issuer = oneiron::authority::HostSlipIssuer::from_secret(secret.as_bytes())?;
    vault.ensure_host_root_slip(&issuer)?;
    let owner = crate::owner::local_owner(vault)?;
    vault.sign_owner_project(&owner, &vault.owner_project_signer(&issuer)?, root)?;
    tracing::info!("the root project took the owner's first signature");
    Ok(())
}

/// Ctrl-C, or SIGTERM where there is one: the stop an operator or a service
/// manager sends.
pub(crate) async fn stop_requested() {
    let interrupt = async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => {},
        () = terminate => {},
    }
    tracing::info!("stop requested; finishing in-flight work");
}
