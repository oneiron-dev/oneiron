//! `oneiron restore` where no vault is yet: the restore on a clean host,
//! its key unlocked the way the owner names and wrapped to this install
//! (moved out of `vault_key` whole).

use std::path::Path;
use std::sync::Arc;

use oneiron::recovery::checkpoint::{CheckpointKey, CheckpointSigner};
use oneiron::world_keys::VaultKeyUnlock;
use oneiron_keystore::DeviceKeystore;
use serde::Serialize;

use super::super::vault_config;
use super::{HostUnlock, backup_key, view};
use crate::config::ServeConfig;
use crate::owner::backup::{self, CustodyAnchorCredentials, RestoreTarget, RestoredFresh};

/// What a restore where no vault was did.
#[derive(Serialize)]
pub(crate) struct FreshRestore {
    #[serde(flatten)]
    restored: RestoredFresh,
    unlocked_with: String,
    /// The restored vault's wraps, with this install's device wrap when its
    /// keystore is on.
    wraps: Vec<view::WrapView>,
}

/// Restores `backup` where no vault is yet, unlocks the new vault's data key
/// the same way and wraps it to this install's keystore. The vault is sealed
/// (OF-570 maximum tier) when the config asks for the tier, under the
/// backup's own data key, and is kept only once its key is wrapped here. A
/// custody anchor door is called with `anchor`, the owner credential the
/// restore was handed on its pipe (`--custody-anchor-credentials-fd`).
pub(crate) fn restore_fresh(
    backup: &Path,
    config: &ServeConfig,
    keystore: Option<Arc<dyn DeviceKeystore>>,
    unlock: &HostUnlock,
    pins: Option<Vec<CheckpointSigner>>,
    anchor: Option<Arc<CustodyAnchorCredentials>>,
) -> anyhow::Result<FreshRestore> {
    let key = match backup_key(backup, &config.vault_path, keystore.as_ref(), unlock, pins)? {
        Some(key) => key,
        None => match keystore {
            Some(keystore) => {
                CheckpointKey::unlock(backup, &VaultKeyUnlock::Device(keystore.as_ref()))
                    .map(|key| key.trusting_device(keystore))
            }
            None => CheckpointKey::unlock_on_this_device(backup, &config.vault_path),
        }
        .map_err(|error| anyhow::anyhow!("backup {} does not open: {error}", backup.display()))?,
    };
    let mut target = vault_config(config);
    target.page_seal = backup::restore_target_seal(RestoreTarget::Fresh {
        maximum_tier: config.maximum_tier,
        key: &key,
    })?;
    let path = &config.vault_path;
    // The custody head beside the backup, checked against the configured
    // anchor (a root or another install's door, called with the piped
    // credential) when there is one, and opened with the kit when the
    // restore was unlocked with it (KS-4A1).
    let mut custody = backup::custody_recovery(backup, &config.backup, anchor);
    if let Some(root) = super::super::recovery_kit::kit_custody_root(unlock) {
        custody = custody.with_kit(root);
    }
    // Before the vault is kept: its key unlocks the same way and is wrapped
    // to this install, so a sealed one is published only once it opens here.
    let (vault, restored) = backup::restore_fresh(backup, path, target, &key, &custody, |vault| {
        let installed = config.keystore.install_on(vault, path);
        unlock.unlock_live(vault)?;
        // A device unlock of a plain vault wraps the key to this install on
        // its own; a sealed vault's key is already held from its page seal.
        let sealed = vault.vault_pages_sealed();
        if installed && (sealed || !matches!(unlock, HostUnlock::Device)) {
            vault.add_vault_key_device()?;
        }
        vault.check_page_custody()
    })?;
    Ok(FreshRestore {
        wraps: view::report(&vault)?.wraps,
        unlocked_with: unlock.name(),
        restored,
    })
}
