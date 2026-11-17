//! Doors for `tests/owner_backup_setting.rs` (FIX-LIST row 5822): the backup
//! host `serve` builds over a vault, and one schedule pass on demand.

use std::path::Path;

use crate::config::BackupConfig;
use crate::server::SyncServer;

/// Attaches the backup host `serve` builds over `vault_path` with the
/// `[backup]` section `backup`: the schedule's fallback while the owner has
/// stored no backup setting, and the plan its backups follow.
pub fn attach_owner_host(
    server: SyncServer,
    vault_path: &Path,
    backup: BackupConfig,
) -> SyncServer {
    let mut config = crate::config::ServeConfig::default();
    config.vault_path = vault_path.to_path_buf();
    config.backup = backup;
    let host =
        crate::owner::schedule::OwnerHost::from_config(&config, oneiron::VaultConfig::device());
    server.with_owner_host(host)
}

/// One schedule pass now, as a tick runs it: whether it took a backup.
///
/// # Errors
///
/// What the pass returns; without an attached host, that none is attached.
pub fn take_if_due_now(server: &SyncServer) -> anyhow::Result<bool> {
    let Some(host) = server.owner_host.as_ref() else {
        anyhow::bail!("no owner host is attached");
    };
    Ok(host.take_if_due(server.vault())?.is_some())
}
