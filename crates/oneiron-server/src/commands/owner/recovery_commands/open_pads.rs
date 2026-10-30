//! `oneiron restore BACKUP --open-pads [--pad-machine ID]` (PAD-2, FIX
//! 10470): on the configured vault, which exists and is stopped, restores
//! nothing. The worlds its latest restore of this backup left Locked open
//! from the custody head beside the backup with the recovery kit (`--unlock
//! kit`) or the key of one of the owner's machines this install still holds,
//! and their pads go into the vault's own custody. The unlock, trust and
//! custody anchor are read as a restore reads them.

use std::path::Path;
use std::sync::Arc;

use oneiron::recovery::checkpoint::{CheckpointKey, CheckpointSigner, PadReopenReport};
use oneiron::world_keys::{HybridSecretKey, VaultKeyUnlock, existing_machine_secret};
use oneiron_keystore::DeviceKeystore;
use serde::Serialize;

use super::super::recovery_kit::{kit_custody_root, kit_custody_seed};
use super::super::{base_vault_config, emit, open_stopped_vault_with, vault_key};
use crate::cli::RestoreArgs;
use crate::config::ServeConfig;
use crate::owner::backup::{self, CustodyAnchorCredentials};
use crate::owner::local_owner;

/// What `--open-pads` did.
#[derive(Serialize)]
struct OpenedPads {
    #[serde(flatten)]
    report: PadReopenReport,
    /// Set when `--pad-machine` named a machine whose key this install does
    /// not hold: that machine opened nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pad_machine_note: Option<String>,
}

/// Opens the worlds the configured vault's latest restore of `backup` left
/// Locked, and reports what it did. A stage that faulted is reported, then
/// returned as an error: what committed before it stands, and the command
/// may be run again.
pub(super) fn open_pads(
    args: &RestoreArgs,
    config: &ServeConfig,
    backup: &Path,
    keystore: Option<Arc<dyn DeviceKeystore>>,
    unlock: &vault_key::HostUnlock,
    pins: Option<Vec<CheckpointSigner>>,
) -> anyhow::Result<()> {
    // A sealed vault (OF-570 maximum tier) opens with this install's
    // keystore, else with the unlock the owner gave.
    let mut vault_config = base_vault_config(config);
    vault_config.page_seal = vault_key::page_seal_at(config, &config.vault_path, Some(unlock))?;
    let vault = open_stopped_vault_with(
        config,
        vault_config,
        "then run `oneiron restore --open-pads` again",
    )?;
    let opened = |result: oneiron::Result<CheckpointKey>| {
        result
            .map_err(|error| anyhow::anyhow!("backup {} does not open: {error}", backup.display()))
    };
    let key =
        match vault_key::backup_key(backup, &config.vault_path, keystore.as_ref(), unlock, pins)? {
            Some(key) => key,
            None => opened(match &keystore {
                Some(keystore) => {
                    CheckpointKey::unlock(backup, &VaultKeyUnlock::Device(keystore.as_ref()))
                        .map(|key| key.trusting_device(Arc::clone(keystore)))
                }
                None => CheckpointKey::unlock_on_this_device(backup, &config.vault_path),
            })?,
        };
    let mut pad_machine_note = None;
    let machine: Option<(oneiron::EntityId, HybridSecretKey)> = match &args.pad_machine {
        Some(id) => {
            let machine = oneiron::EntityId::from_hex(id)
                .map_err(|error| anyhow::anyhow!("--pad-machine {id}: {error}"))?;
            let vault_id = vault.authority_fold()?.vault_id.ok_or_else(|| {
                anyhow::anyhow!("the vault has no authority genesis yet: no machine key names it")
            })?;
            let keystore = match &keystore {
                Some(keystore) => Arc::clone(keystore),
                None => {
                    oneiron_keystore::default_platform_keystore(&[config.vault_path.as_path()])?
                }
            };
            let secret = existing_machine_secret(keystore.as_ref(), vault_id, *machine.as_bytes())?;
            if secret.is_none() {
                pad_machine_note = Some(format!(
                    "this install holds no key of machine {id}: it opened nothing"
                ));
            }
            secret.map(|secret| (machine, secret))
        }
        None => None,
    };
    // The custody head beside the backup, checked against the configured
    // anchor when there is one, opened with the kit when the restore was
    // unlocked with it and with the named machine's key.
    let anchor = CustodyAnchorCredentials::handed(args.serve.custody_anchor_credentials_fd)?;
    let mut custody = backup::custody_recovery(backup, &config.backup, anchor);
    if let Some(root) = kit_custody_root(unlock) {
        custody = custody.with_kit(root);
    }
    if let Some((machine, secret)) = &machine {
        custody = custody.with_machine(*machine, secret);
    }
    let seed = kit_custody_seed(unlock);
    custody = backup::custody_from_home(custody, backup, args.custody_home.as_deref(), seed)?;
    let owner = local_owner(&vault)?;
    let report = vault.reopen_restore_pads_as(&owner, None, backup, &key, &custody)?;
    let faults = report.faults.len();
    emit(&OpenedPads {
        report,
        pad_machine_note,
    })?;
    anyhow::ensure!(
        faults == 0,
        "{faults} stage(s) of the pad reopen faulted; what committed stands, and the command may \
         run again"
    );
    Ok(())
}
