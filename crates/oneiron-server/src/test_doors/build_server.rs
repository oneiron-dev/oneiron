//! Door for `tests/serve_usage_metering.rs`: the server plain and embedded
//! serve build over a vault (`commands::build_server`).

use std::path::Path;
use std::sync::Arc;

use crate::server::SyncServer;

/// Builds the server `serve` builds over `vault` at `vault_path`, with the
/// default `[serve]` settings and `auth_secret`. Built only: no listener
/// binds and no worker starts. Default settings name no GPU pool, so there is
/// no health poller to keep.
///
/// # Errors
///
/// What `build_server` returns.
pub async fn build_served_server(
    vault: Arc<oneiron::Vault>,
    vault_path: &Path,
    auth_secret: Option<String>,
) -> anyhow::Result<SyncServer> {
    let mut config = crate::config::ServeConfig::default();
    config.vault_path = vault_path.to_path_buf();
    config.auth_secret = auth_secret;
    let server_config = config.sync_server_config();
    let owner_host =
        crate::owner::schedule::OwnerHost::from_config(&config, oneiron::VaultConfig::device());
    let (server, _gpu_poller) = crate::commands::build_server(
        vault,
        &config,
        server_config,
        owner_host,
        &crate::config::ServeArgs::default(),
    )
    .await?;
    Ok(server)
}
