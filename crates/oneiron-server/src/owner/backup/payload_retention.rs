//! Checkpoint payload retention beside a vault's backups (KS7-5): each
//! backup's kept-generation inventory lands beside it with the artifact
//! (`.<snapshot id>.payload-inventory`), naming the compartments its payload
//! is sealed under. A prune reads where each backup it will take keeps its
//! inventory before the backup goes, removes the inventory once the backup
//! is gone, then hands every backup it still keeps to the engine, which
//! retires each staged leaf retirement no kept backup still names
//! ([`oneiron::Vault::retire_unkept_checkpoint_payloads`]).
//!
//! Nothing here holds a backup or refuses a prune: an inventory that is
//! missing or does not read keeps every leaf it might name, so only a key's
//! retirement waits, and a fault is logged for the next prune.

use std::path::PathBuf;

use super::{BackupPlan, BackupRecord, list};

/// Where each of `records` keeps its payload inventory, read from its head
/// before a prune takes it: by file.
pub(super) fn inventories_of(records: &[BackupRecord]) -> Vec<(String, PathBuf)> {
    records
        .iter()
        .filter_map(|record| {
            oneiron::Vault::checkpoint_payload_inventory(&record.path)
                .map(|inventory| (record.file.clone(), inventory))
        })
        .collect()
}

/// After a prune: the inventory of each backup in `pruned` goes, from
/// `inventories`, then each staged payload leaf retirement no backup `plan`
/// still keeps names is carried out. Warning-only.
pub(super) fn settle(
    vault: &oneiron::Vault,
    plan: &BackupPlan,
    pruned: &[String],
    inventories: Vec<(String, PathBuf)>,
) {
    for (file, inventory) in inventories {
        if !pruned.contains(&file) {
            continue;
        }
        match std::fs::remove_file(&inventory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => tracing::warn!(
                reason = "backup_payload_inventory_kept",
                error = %error,
                "a pruned backup's payload inventory did not go; it names leaves no backup keeps"
            ),
        }
    }
    let kept: Vec<PathBuf> = match list(plan) {
        Ok(records) => records.into_iter().map(|record| record.path).collect(),
        Err(error) => {
            tracing::warn!(
                reason = "backup_payload_retention_deferred",
                error = %format!("{error:#}"),
                "the kept backups did not list; payload leaf retention waits for the next prune"
            );
            return;
        }
    };
    if let Err(error) = vault.retire_unkept_checkpoint_payloads(&kept) {
        tracing::warn!(
            reason = "backup_payload_retention_deferred",
            kind = ?error.kind(),
            "payload leaf retention waits for the next prune"
        );
    }
}
