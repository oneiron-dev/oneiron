//! A dedicated replica target's own page seal and local key custody.

use oneiron::Vault;

use crate::config::ServeConfig;

/// Reuses init's seal and device-wrap doors without init's root mint or its
/// unfinished-creation removal. No later import failure may delete this target.
pub(crate) fn open(config: &ServeConfig) -> anyhow::Result<Vault> {
    let path = &config.vault_path;
    let mut resolved = config.base_vault_config();
    resolved.page_seal = super::owner::prepare_page_seal(config, None)?;
    let target = Vault::open_owned(path, resolved)?;
    anyhow::ensure!(
        target.is_unstarted_replica_target()?,
        "the selected replica target's authority has already started"
    );
    config.keystore.install_on_boot(&target, path)?;
    super::owner::ensure_page_seal_wrapped(&target, path)?;
    Ok(target)
}
