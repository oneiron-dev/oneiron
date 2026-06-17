use std::net::SocketAddr;
use std::sync::Arc;

use axum::http::HeaderValue;
use clap::Parser;
use tower_http::cors::{AllowOrigin, CorsLayer};
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
        allow_unauthenticated: args.insecure_allow_unauthenticated,
        allowed_origins: args.allowed_origins,
        ..Default::default()
    };
    if server_config.auth_secret.is_none() && !server_config.allow_unauthenticated {
        tracing::warn!(
            "server started with no auth_secret and allow_unauthenticated=false — refusing all requests; set ONEIRON_AUTH_SECRET or pass --insecure-allow-unauthenticated for local dev"
        );
    }
    let cors_layer = build_cors_layer(&server_config)?;

    // Reloads persisted CRDT state (d:root + d:w:* in sync_state) — a fresh
    // boot must not silently discard previously relayed updates/tombstones.
    let sync_server = Arc::new(
        SyncServer::new(Arc::new(vault), server_config)
            .map_err(|e| anyhow::anyhow!("sync server init failed: {e}"))?,
    );

    // Build Axum router
    let app = build_app(sync_server).layer(cors_layer);

    let addr: SocketAddr = format!("{}:{}", args.host, args.port).parse()?;
    tracing::info!(%addr, "listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

fn build_cors_layer(config: &SyncServerConfig) -> anyhow::Result<CorsLayer> {
    let allowed_origins = parse_allowed_origins(&config.allowed_origins)?;

    if allowed_origins.is_empty() {
        Ok(CorsLayer::new())
    } else {
        Ok(CorsLayer::new().allow_origin(AllowOrigin::list(allowed_origins)))
    }
}

fn parse_allowed_origins(origins: &[String]) -> anyhow::Result<Vec<HeaderValue>> {
    origins
        .iter()
        .filter_map(|origin| {
            let trimmed = origin.trim();
            (!trimmed.is_empty()).then_some(trimmed)
        })
        .map(|origin| {
            if origin == "*" {
                anyhow::bail!("wildcard CORS origin is not allowed");
            }
            origin
                .parse::<HeaderValue>()
                .map_err(|e| anyhow::anyhow!("invalid CORS origin {origin:?}: {e}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_cors_origin_list_stays_restrictive() {
        let config = SyncServerConfig::default();

        let parsed = parse_allowed_origins(&config.allowed_origins).unwrap();

        assert!(parsed.is_empty());
        assert!(build_cors_layer(&config).is_ok());
    }

    #[test]
    fn configured_cors_origin_is_parsed() {
        let config = SyncServerConfig {
            allowed_origins: vec!["https://app.example".to_owned()],
            ..Default::default()
        };

        assert_eq!(
            parse_allowed_origins(&config.allowed_origins).unwrap(),
            vec![HeaderValue::from_static("https://app.example")]
        );
        assert!(build_cors_layer(&config).is_ok());
    }

    #[test]
    fn wildcard_cors_origin_is_rejected() {
        let config = SyncServerConfig {
            allowed_origins: vec!["*".to_owned()],
            ..Default::default()
        };

        let error = build_cors_layer(&config).unwrap_err().to_string();

        assert!(error.contains("wildcard CORS origin is not allowed"));
    }
}
