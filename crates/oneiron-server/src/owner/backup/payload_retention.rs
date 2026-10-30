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
//!
//! An inventory can outlive its artifact: a crash between the inventory
//! landing and the artifact's, or an inventory that would not go. Each prune
//! sweeps the inventories no backup in its directory names ([`sweep`]).

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use super::{BackupPlan, BackupRecord, FILE_SUFFIX, PARTIAL_SUFFIX, list, sync_dir};

/// The suffix of a payload inventory: `.<snapshot id hex>.payload-inventory`.
const INVENTORY_SUFFIX: &str = ".payload-inventory";

/// How long an inventory no backup names stays before a sweep takes it. A
/// take lands its inventory just before it starts its artifact, and any
/// vault's take may share the directory, so a young one may be landing.
const ORPHAN_INVENTORY_GRACE: Duration = Duration::from_secs(24 * 60 * 60);

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

/// Removes the payload inventories in `plan`'s directory that no backup
/// there names: every artifact in it, of any vault, and every partial one
/// whose head reads, is read for the inventory it names first. One a backup
/// names stays; so does every one while an artifact's head does not read,
/// and one younger than [`ORPHAN_INVENTORY_GRACE`]. The holds are read and
/// each goes while the vault's writer is held, as a checkpoint fact's sweep
/// does. A missing inventory keeps every leaf, so a sweep only lets a
/// retirement go sooner. Warning-only: a sweep never fails a prune.
pub(super) fn sweep(vault: &oneiron::Vault, plan: &BackupPlan) {
    if let Err(error) = sweep_orphans(vault, plan) {
        tracing::warn!(
            reason = "backup_payload_inventory_sweep_failed",
            error = %format!("{error:#}"),
            "payload inventories whose backup is gone were not swept; the next prune sweeps again"
        );
    }
}

fn sweep_orphans(vault: &oneiron::Vault, plan: &BackupPlan) -> anyhow::Result<()> {
    let entries = match std::fs::read_dir(&plan.dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let mut named: BTreeSet<OsString> = BTreeSet::new();
    let mut inventories = Vec::new();
    for entry in entries {
        let entry = entry?;
        let file = entry.file_name();
        let Some(name) = file.to_str() else {
            continue;
        };
        if name.ends_with(FILE_SUFFIX) || name.ends_with(PARTIAL_SUFFIX) {
            match oneiron::Vault::checkpoint_payload_inventory(&entry.path()) {
                Some(inventory) => named.extend(inventory.file_name().map(OsString::from)),
                // An artifact whose head does not read may name any of them.
                None if name.ends_with(FILE_SUFFIX) => return Ok(()),
                None => {}
            }
        } else if is_inventory(name)
            && matches!(entry.file_type(), Ok(kind) if kind.is_file())
            && entry
                .metadata()
                .ok()
                .and_then(|metadata| metadata.modified().ok())
                .and_then(|modified| modified.elapsed().ok())
                .is_some_and(|age| age > ORPHAN_INVENTORY_GRACE)
        {
            inventories.push(file);
        }
    }
    let orphans: Vec<OsString> = inventories
        .into_iter()
        .filter(|file| !named.contains(file))
        .collect();
    if orphans.is_empty() {
        return Ok(());
    }
    vault.with_backup_hold_exclusion(|holds| -> anyhow::Result<()> {
        if holds.keeps_backups() {
            return Ok(());
        }
        let mut swept = false;
        for file in &orphans {
            match std::fs::remove_file(plan.dir.join(file)) {
                Ok(()) => swept = true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => tracing::warn!(
                    reason = "backup_payload_inventory_kept",
                    error = %error,
                    "a payload inventory no backup names did not go"
                ),
            }
        }
        if swept {
            sync_dir(&plan.dir)?;
        }
        Ok(())
    })?
}

/// Whether `name` is a payload inventory's: a dot, a snapshot id in 64
/// lowercase hex digits, then the suffix.
fn is_inventory(name: &str) -> bool {
    name.strip_prefix('.')
        .and_then(|rest| rest.strip_suffix(INVENTORY_SUFFIX))
        .is_some_and(|id| {
            id.len() == 64
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}
