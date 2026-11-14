//! Door for `tests/managed_serve_usage_metering.rs`: the usage meter bind a
//! managed start runs on its built server before any worker starts (census
//! L8-12), under a tenancy the test names.

use oneiron_vault_contract::tenancy::VaultTenancy;

use crate::server::SyncServer;

/// Binds `server`'s usage meter as a managed start under `tenancy` binds it.
/// On this base a managed start binds none: `managed/state_serve/coordinator.rs`
/// builds its server with no meter.
pub fn bind_managed_usage_metering(server: &SyncServer, tenancy: VaultTenancy) {
    let _ = (server, tenancy);
}
