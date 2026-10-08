//! The unmanaged serve path: open the vault, build the server and its
//! workers, serve until a stop signal, then stop every worker cleanly.

use std::net::SocketAddr;
use std::sync::Arc;

use super::{
    build_cors_layer, reembed, resolve_dict_search_paths, should_warn_public_bind_without_auth,
    weak_auth_secret_warning,
};
use crate::build_app;
use crate::config::ServeConfig;
use crate::managed::{self, ServeListener};
use crate::server::SyncServer;

/// How long open connections get to finish after a stop is requested.
const DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

pub(super) async fn serve_with_config(config: ServeConfig) -> anyhow::Result<()> {
    use oneiron_vault_contract::host::{Host, HostLimits};

    tracing::info!(
        vault_path = %config.vault_path.display(),
        dimensions = config.dimensions,
        "starting oneiron sync server"
    );

    let dicts = resolve_dict_search_paths(&config.dict_search_paths);
    if let Some(warning) = dicts.warning {
        tracing::warn!(dict_paths = ?dicts.paths, "{warning}");
    } else {
        tracing::info!(dict_paths = ?dicts.paths, "using CJK dictionary search paths");
    }

    let mut vault_config = config.vault_config();
    vault_config.dict_search_paths = dicts.paths;
    let owner_host = crate::owner::schedule::OwnerHost::from_config(&config, vault_config.clone());
    let vault = oneiron::Vault::open_owned(&config.vault_path, vault_config)
        .map_err(reembed::with_model_change_remedy)?;

    let server_config = config.sync_server_config();
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
    let embedder_config = config.embedder.clone();
    let embedder =
        tokio::task::spawn_blocking(move || crate::embedder::build_slot(embedder_config.as_ref()))
            .await
            .map_err(|e| anyhow::anyhow!("embedder slot task failed: {e}"))??;
    let tagger = crate::oneironer::build_slot_off_runtime(config.oneironer.clone()).await?;

    // Reloads persisted CRDT state (d:root + d:w:* in sync_state) — a fresh
    // boot must not silently discard previously relayed updates/tombstones.
    let sync_server = SyncServer::new(Arc::new(vault), server_config)
        .map_err(|e| anyhow::anyhow!("sync server init failed: {e}"))?
        .with_embedder(embedder)
        .with_tagger(tagger)
        .with_owner_host(owner_host);
    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    // Same bind, named through the listener enum managed mode also uses.
    // `Tcp` is the only variant this path can produce, so unmanaged serve
    // still binds host:port and nothing else. Bound before any worker
    // starts, so a refused bind leaves nothing running.
    let listener = ServeListener::Tcp(addr).bind().await?;
    let managed::BoundServeListener::Tcp(listener) = listener else {
        anyhow::bail!("unmanaged serve requires a TCP listener");
    };
    let mut host = oneiron_vault_contract::host_adapters::InProcessHost::new(
        listener.into_std()?,
        HostLimits::unbounded(),
        || Ok(()),
        || Ok(()),
    );
    let listener = tokio::net::TcpListener::from_std(host.listener()?)?;
    tracing::info!(%addr, "listening");
    // Model seats, the Dreamer and the workflow pump, from `[models]`. With
    // no section every seat stays empty and the model-free server is whole.
    // A startup error below drops `ai`, which tells its workers to stop.
    let (sync_server, ai) =
        crate::ai_host::AiHost::attach(sync_server, config.models.as_ref()).await;
    let sync_server = Arc::new(sync_server);
    let linear_handle = crate::linear_host::spawn(sync_server.clone()).await?;
    let lifecycle_handle = sync_server.spawn_lifecycle_scheduler();
    let mut workers = sync_server.spawn_slot_workers();
    workers.extend(sync_server.spawn_backup_schedule(crate::owner::schedule::SCHEDULE_TICK));
    let app = build_app(sync_server).layer(cors_layer);
    host.ready()?;
    // Open sockets may never close by themselves, so the drain is bounded.
    let (stopping, mut stopped) = tokio::sync::watch::channel(false);
    let serving = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        stop_requested().await;
        let _ = stopping.send(true);
    });
    let result = tokio::select! {
        result = serving => result,
        () = async {
            let _ = stopped.wait_for(|stop| *stop).await;
            tokio::time::sleep(DRAIN_GRACE).await;
        } => {
            tracing::warn!("connections still open after the drain grace; stopping anyway");
            Ok(())
        }
    };
    // A pass or step in flight reaches its own boundary before this returns.
    ai.shutdown().await;
    host.on_stop()?;
    lifecycle_handle.abort();
    let _ = lifecycle_handle.await;
    if let Some(handle) = linear_handle {
        handle.abort();
        let _ = handle.await;
    }
    for handle in workers {
        handle.abort();
        let _ = handle.await;
    }
    result?;

    Ok(())
}

/// Ctrl-C, or SIGTERM where there is one: the stop an operator or a service
/// manager sends.
async fn stop_requested() {
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
