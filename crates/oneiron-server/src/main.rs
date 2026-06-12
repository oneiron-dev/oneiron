use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use oneiron_server::build_app;
use oneiron_server::config::{CliArgs, SyncServerConfig};
use oneiron_server::server::SyncServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = CliArgs::parse();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level)),
        )
        .init();

    tracing::info!(
        vault_path = %args.vault_path,
        dimensions = args.dimensions,
        "starting oneiron sync server"
    );

    // Open vault
    let mut vault_config = oneiron::VaultConfig::server();
    vault_config.dimensions = args.dimensions;
    vault_config.map_size = args.map_size;

    let vault = oneiron::Vault::open(&args.vault_path, vault_config)?;

    // Build sync server state
    let server_config = SyncServerConfig {
        auth_secret: args.auth_secret,
        ..Default::default()
    };

    // Reloads persisted CRDT state (d:root + d:w:* in sync_state) — a fresh
    // boot must not silently discard previously relayed updates/tombstones.
    let sync_server = Arc::new(
        SyncServer::new(Arc::new(vault), server_config)
            .map_err(|e| anyhow::anyhow!("sync server init failed: {e}"))?,
    );

    // Build Axum router
    let app = build_app(sync_server).layer(tower_http::cors::CorsLayer::permissive());

    let addr: SocketAddr = format!("{}:{}", args.host, args.port).parse()?;
    tracing::info!(%addr, "listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
