mod api;
mod broadcast;
mod config;
mod handler;
mod protocol;
mod server;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::config::CliArgs;
use crate::server::SyncServer;

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
    let vault_config = oneiron::VaultConfig {
        dimensions: args.dimensions,
        embedding_model: None,
        map_size: args.map_size,
        max_readers: 126,
        hnsw: oneiron::HnswConfig::default(),
    };

    let vault = oneiron::Vault::open(&args.vault_path, vault_config)?;

    // Build sync server state
    let server_config = config::SyncServerConfig {
        auth_secret: args.auth_secret,
        ..Default::default()
    };

    let sync_server = Arc::new(SyncServer::new(vault, server_config));

    // Build Axum router
    let app = Router::new()
        .merge(handler::ws_routes(sync_server.clone()))
        .merge(api::api_routes(sync_server.clone()))
        .layer(tower_http::cors::CorsLayer::permissive());

    let addr: SocketAddr = format!("{}:{}", args.host, args.port).parse()?;
    tracing::info!(%addr, "listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
