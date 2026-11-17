//! Doors for `tests/serve_usage_metering.rs` and
//! `tests/managed_serve_usage_metering.rs`: the server plain and embedded
//! serve build over a vault (`commands::build_server`), and the usage meter
//! bind a managed start runs on its built server (census L8-12).

use std::path::Path;
use std::sync::Arc;

use oneiron_vault_contract::tenancy::VaultTenancy;

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

/// For `tests/chat_model_call_turn_link.rs` (HANDOFF-CONTEXT): starts the
/// turn-action worker of `ai`, attached to `server`, as `serve` does once it
/// has built the server (`commands/serve/workers.rs`), so a queued Continue
/// or Retry is answered.
pub fn bind_turn_actions(ai: &crate::ai_host::AiHost, server: &Arc<SyncServer>) {
    ai.bind_turn_actions(server);
}

/// Binds `server`'s usage meter as a managed start under `tenancy` binds it:
/// to the tenancy's payer, before any worker starts.
pub fn bind_managed_usage_metering(server: &SyncServer, tenancy: VaultTenancy) {
    crate::managed::usage_meter::bind_tenancy_usage_metering(server, tenancy);
}
