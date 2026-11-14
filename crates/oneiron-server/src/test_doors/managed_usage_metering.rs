//! Door for `tests/managed_serve_usage_metering.rs`: the usage meter bind a
//! managed start runs on its built server before any worker starts (census
//! L8-12), under a tenancy the test names.

use oneiron_vault_contract::tenancy::VaultTenancy;

use crate::server::SyncServer;

/// Binds `server`'s usage meter as a managed start under `tenancy` binds it.
pub fn bind_managed_usage_metering(server: &SyncServer, tenancy: VaultTenancy) {
    crate::managed::usage_meter::bind_tenancy_usage_metering(server, tenancy);
}
