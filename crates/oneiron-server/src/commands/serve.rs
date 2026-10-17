//! The unmanaged serve path: open the vault, build the server and its
//! workers, serve until a stop signal, then stop every worker cleanly.

use std::net::SocketAddr;
use std::sync::Arc;

use super::{
    build_cors_layer, reembed, resolve_dict_search_paths, should_warn_public_bind_without_auth,
    weak_auth_secret_warning,
};
use crate::build_app;
use crate::build_artifact_app;
use crate::config::ServeConfig;
use crate::managed;
use crate::server::SyncServer;

/// How long open connections get to finish after a stop is requested.
const DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

/// The plist's `Sockets` key and the keychain service launchd's daemon reads
/// its secrets from, as `deploy/launchd/com.oneiron.server.plist` names them.
const LAUNCHD_SOCKET: &str = "Listeners";
const KEYCHAIN_SERVICE: &str = "com.oneiron.server";

/// `config_file` is the file `config` was read from, which the server's
/// runtime file names for a client that queues imports to it.
pub(super) async fn serve_with_config(
    mut config: ServeConfig,
    config_file: Option<std::path::PathBuf>,
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

    let dicts = resolve_dict_search_paths(&config.dict_search_paths);
    if let Some(warning) = dicts.warning {
        tracing::warn!(dict_paths = ?dicts.paths, "{warning}");
    } else {
        tracing::info!(dict_paths = ?dicts.paths, "using CJK dictionary search paths");
    }

    let mut vault_config = config.vault_config();
    vault_config.dict_search_paths = dicts.paths;
    let owner_host = crate::owner::schedule::OwnerHost::from_config(&config, vault_config.clone());
    #[cfg(unix)]
    let import_queue = super::history_import::queue::ImportQueue::from_config(&config);
    #[cfg(unix)]
    let folder_rescans = super::history_import::notes::folder::FolderRescans::from_config(&config);
    let vault = oneiron::Vault::open_owned(&config.vault_path, vault_config)
        .map_err(reembed::with_model_change_remedy)?;
    managed::warn_if_reader_table_short(&vault);
    config.keystore.install_on(&vault, &config.vault_path);
    if let Some(embedding) = &config.embedding {
        embedding.apply_to(&vault)?;
    }
    #[cfg(unix)]
    if let Err(error) = vault.collect_result_bodies(4096) {
        tracing::warn!(%error, "result body collection at start failed");
    }

    let server_config = config.sync_server_config();
    if let Err(error) = sign_root_project(&vault, server_config.auth_secret.as_deref()) {
        tracing::warn!(%error, "the root project was not signed; it stays unsigned until the next start");
    }
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
    //
    // On a blocking thread because the endpoint probe is a blocking HTTP call,
    // which must not run on a runtime worker.
    // The batch lane's rented GPU pods (ARCH-0019 §5), when `[gpu]` names
    // them: the pool polls their health while serve runs, and the endpoint
    // embedder sends its document batches through a lease on one. A vault
    // bound to an account has each pod's answer sealed to that account.
    let gpu = config
        .gpu
        .clone()
        .map(crate::runtime::GpuPool::new)
        .transpose()?;
    let gpu_poller = gpu
        .as_ref()
        .map(crate::runtime::GpuPool::spawn_health_poller);
    let gpu_route = gpu.map(|pool| (pool, vault.derivation_scope().ok()));
    let embedder_config = config.embedder.clone();
    let embedder = crate::logging::off_runtime("embedder slot task", move || {
        // The server's sink before a host chooses one: the log.
        let receipts = Arc::new(crate::models::ServerReceipts::default());
        let slot = crate::embedder::build_slot(embedder_config.as_ref(), receipts)?;
        if let (Some(slot), Some((pool, scope))) = (&slot, gpu_route) {
            crate::embedder::route_batches_through(slot, pool, scope)?;
        }
        anyhow::Ok(slot)
    })
    .await??;
    let tagger = crate::oneironer::build_slot_off_runtime(config.oneironer.clone()).await?;

    // Reloads persisted CRDT state (d:root + d:w:* in sync_state) — a fresh
    // boot must not silently discard previously relayed updates/tombstones.
    let sync_server = SyncServer::new(Arc::new(vault), server_config)
        .map_err(|e| anyhow::anyhow!("sync server init failed: {e}"))?
        .with_embedder(embedder)
        .with_tagger(tagger)
        .with_owner_host(owner_host)
        .with_browser_guest(
            config
                .browser
                .as_ref()
                .map(crate::config::BrowserConfig::guest),
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
        }));
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
    // Model seats, the Dreamer and the workflow pump, from `[models]`. With
    // no section every seat stays empty and the model-free server is whole.
    // A startup error below drops `ai`, which tells its workers to stop.
    let (sync_server, ai) =
        crate::ai_host::AiHost::attach(sync_server, config.models.as_ref()).await;
    let sync_server = Arc::new(sync_server);
    // The skill-edit gate's replay judge, on the ladder the server just built (OF-495).
    crate::replay_judge::register(&sync_server, config.skills.live_pulls_per_axis);
    // The vault's first oversight receipts, before the host's own workers
    // start: a vault that cannot sign them never reports ready.
    let oversight = sync_server
        .start_healer_oversight(crate::server::HEALER_OVERSIGHT_EVERY, || Some(()))
        .await?;
    let linear_handle = crate::linear_host::spawn(sync_server.clone()).await?;
    // A wake pass keeps a plugged-in laptop awake until it ends; on battery
    // normal idle sleep holds (ruled 2026-10-08).
    let awake = host.keep_awake(AwakePolicy::default());
    // A live model run holds the same assertion through each admitted call,
    // not only a wake pass (Docs Q18).
    oneiron_vault_contract::host_adapters::hold_awake_for_runs({
        let awake = awake.clone();
        move || Box::new(awake.hold()) as Box<dyn Send>
    });
    let admit = crate::server::admit_every_pass();
    let lifecycle = sync_server.spawn_lifecycle_scheduler(Arc::new(move || {
        let pass = admit()?;
        Some(Box::new((pass, awake.hold())) as Box<dyn Send>)
    }));
    let mut workers = sync_server.spawn_slot_workers();
    workers.extend(gpu_poller);
    workers.push(sync_server.spawn_board_publisher());
    // Crossed thresholds ask the ladder whether everything is okay (OF-520).
    workers.push(crate::wire_health::spawn(&sync_server));
    // Due standing questions are answered through the ladder (OF-506).
    workers.push(crate::decision_graph::spawn(&sync_server));
    // Uncertain identities are decided, or asked of the person (OF-123).
    workers.push(crate::ai_host::identity::spawn(&sync_server));
    // Failure cases and blocked reports reach the Coach as proposed heals (OF-418).
    workers.push(crate::ai_host::coach_heal::spawn(&sync_server));
    // The nightly Coach jobs that need the host's model or rules (OF-420).
    workers.push(crate::ai_host::coach_host::spawn(&sync_server));
    // Failure signals reach the deployment's publisher (OF-380).
    workers.extend(crate::ai_host::failure_signals::spawn(
        &sync_server,
        crate::ai_host::failure_signals::FailureSignalHost::new(
            &config.failure_signals,
            config.privacy_posture == oneiron::HostingPrivacyPosture::Hosted,
            std::env::var("ONEIRON_FAILURE_SIGNALS_TOKEN")
                .ok()
                .filter(|token| !token.is_empty())
                .map(zeroize::Zeroizing::new),
        ),
        crate::server::admit_every_pass(),
    ));
    workers.push(sync_server.spawn_connector_event_worker(crate::server::admit_every_pass()));
    // Approved sends leave through the connector executor (OF-187).
    workers.push(sync_server.spawn_connector_send_worker(crate::server::admit_every_pass()));
    // Checked built-in channels and their provider webhooks (OF-519).
    workers.push(crate::builtin_host::spawn(
        &sync_server,
        crate::server::admit_every_pass(),
    ));
    workers.extend(sync_server.spawn_backup_schedule(crate::owner::schedule::SCHEDULE_TICK));
    // Documents whose signing finished are sealed as a task (OF-415).
    #[cfg(unix)]
    workers.push(crate::api::spawn_esign_seal_worker(Arc::clone(
        &sync_server,
    )));
    workers.push(crate::api::spawn_esign_hold_worker(Arc::clone(
        &sync_server,
    )));
    #[cfg(unix)]
    workers.extend(import_queue.map(|queue| queue.spawn(Arc::clone(&sync_server))));
    // Attached folders rescan after the import queue starts (OF-554).
    #[cfg(unix)]
    workers.extend(folder_rescans.map(|rescans| rescans.spawn(Arc::clone(&sync_server))));
    // Open sockets may never close by themselves, so the drain is bounded.
    let (stopping, mut stopped) = tokio::sync::watch::channel(false);
    // Fact hooks (ARCH-0080) run unless `--no-hooks`; they stop with serve.
    #[cfg(feature = "code-sandbox-wasmtime")]
    if config.hooks {
        workers.extend(spawn_fact_hooks(&sync_server, stopped.clone()).await);
    }
    if !config.hooks {
        sync_server.vault().suppress_verb_hooks();
    }
    // The API's CORS stays the API's: the artifact origin is never granted.
    let artifact_app = build_artifact_app(sync_server.clone());
    let questions = Arc::clone(sync_server.wire_telemetry.limit_questions());
    #[cfg(unix)]
    let vault_id = super::local_servers::vault_id(sync_server.vault());
    // The server's own voice loop (OF-410): off unless `[models.voice]`
    // names its socket.
    #[cfg(unix)]
    let voice = crate::voice_host::VoiceBoot::start(
        &sync_server,
        config.models.as_ref().map(|models| &models.voice),
    );
    let mesh_server = Arc::clone(&sync_server);
    let app = build_app(sync_server).layer(cors_layer);
    // The paired-machine mesh listener (OF-535): off unless the host names
    // its bind address.
    let mesh = crate::handler::mesh::start(
        mesh_server,
        &crate::handler::mesh::MeshConfig::from_env()?,
        &app,
        config.limits.connections().header_read_timeout,
    )
    .await?;
    host.ready()?;
    // Ready and bound: a client on this host can find it now. The file goes
    // when this returns, a clean stop or a late startup error alike.
    #[cfg(unix)]
    let _registered =
        super::local_servers::register(vault_id, bound, &config.vault_path, config_file.as_deref());
    #[cfg(not(unix))]
    let _ = config_file;
    let stop = |mut stopped: tokio::sync::watch::Receiver<bool>| async move {
        let _ = stopped.wait_for(|stop| *stop).await;
    };
    let (api_stop, artifact_stop) = (stop(stopped.clone()), stop(stopped.clone()));
    // Connections are admitted, and their headers timed, before any route
    // runs. Both listeners draw on one pool, so the descriptor floor and each
    // address's unauthenticated share hold for the daemon, not per socket.
    let limits = config.limits.connections();
    let pool = crate::http_listener::ConnectionPool::new(&limits, questions);
    let api = crate::http_listener::serve_with_pool(listener, app, &pool, limits, api_stop);
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
    if let Some(mesh) = mesh {
        mesh.stop().await;
    }
    // A voice call in flight ends through its own teardown before the
    // models it speaks on stop.
    #[cfg(unix)]
    if let Some(voice) = voice {
        voice.stop().await;
    }
    // A pass or step in flight reaches its own boundary before this returns.
    ai.shutdown().await;
    // A receipt write already admitted ends before the process does.
    oversight.stop().await;
    host.on_stop()?;
    // A housekeeping pass in flight stops at its next sweep or page.
    lifecycle.stop().await;
    if let Some(handle) = linear_handle {
        handle.abort();
        let _ = handle.await;
    }
    for handle in workers {
        handle.abort();
        let _ = handle.await;
    }

    Ok(())
}

/// Builds the hook sandbox off the runtime (it compiles and probes the
/// component) and starts the fact-hook runner. A sandbox that fails to load
/// starts no runner.
#[cfg(feature = "code-sandbox-wasmtime")]
async fn spawn_fact_hooks(
    server: &Arc<SyncServer>,
    stop: tokio::sync::watch::Receiver<bool>,
) -> Option<tokio::task::JoinHandle<()>> {
    use oneiron::runtime_hooks::{FactHookRunner, sandbox};
    let built = crate::logging::off_runtime("hook sandbox", || {
        let (bytes, pin) = sandbox::hook_component_bytes();
        sandbox::HookSandbox::from_component(bytes, pin).map_err(anyhow::Error::from)
    })
    .await
    .and_then(|built| built);
    match built {
        Ok(sandbox) => {
            let runtime: Arc<dyn oneiron::runtime_hooks::HookBodyRuntime> = Arc::new(sandbox);
            // `vault.hooks.replay` replays on the runner's own sandbox.
            let _ = server.hook_runtime.set(Arc::clone(&runtime));
            // Verb hooks run on it too: one sandbox per process.
            server.vault().install_hook_runtime(Arc::clone(&runtime));
            // Generative fact hooks ask `ai.verdict` on serve's own ladder.
            let verdict: Arc<dyn oneiron::runtime_hooks::HookVerdict> =
                Arc::new(crate::hook_verdict::ServerHookVerdict::new(server));
            Some(FactHookRunner::spawn(
                Arc::clone(server.vault()),
                runtime,
                Some(verdict),
                stop,
            ))
        }
        Err(error) => {
            tracing::warn!(%error, "hook sandbox did not load; fact hooks are off");
            None
        }
    }
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
fn sign_root_project(vault: &oneiron::Vault, secret: Option<&str>) -> anyhow::Result<()> {
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
