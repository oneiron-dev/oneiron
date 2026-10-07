//! Local backups of one vault: take, list, prune, rehearse and restore.
//!
//! A backup is the engine's checkpoint image (`Vault::snapshot_checkpoint`):
//! canonical rows only, never indexes, never exterior key custody. Each one is
//! written under a hidden partial name and renamed into place, so a listing
//! never shows a half-written file. File names carry the vault's directory
//! name, so two vaults can share one backup directory without pruning each
//! other's files.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use oneiron::recovery::checkpoint::RestoreReason;
use serde::Serialize;

use super::stamp::{file_stamp, now_unix_ms, parse_file_stamp, rfc3339};

const FILE_SUFFIX: &str = ".oneiron-backup";
const PARTIAL_SUFFIX: &str = ".partial";

/// Where one vault's backups live and how many are kept.
#[derive(Clone, Debug)]
pub(crate) struct BackupPlan {
    pub(crate) dir: PathBuf,
    /// File-name prefix scoping listing and pruning to this vault.
    pub(crate) label: String,
    pub(crate) keep: usize,
}

impl BackupPlan {
    pub(crate) fn new(vault_path: &Path, dir: PathBuf, keep: usize) -> Self {
        let label = vault_path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "vault".to_owned())
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        Self { dir, label, keep }
    }
}

/// One backup file.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct BackupRecord {
    pub(crate) file: String,
    pub(crate) path: PathBuf,
    pub(crate) bytes: u64,
    /// RFC 3339 UTC time the backup was taken.
    pub(crate) taken: String,
    #[serde(skip)]
    pub(crate) taken_ms: u64,
}

/// What `backup` did.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct BackupOutcome {
    pub(crate) backup: BackupRecord,
    /// BLAKE3 of the checkpoint image; a rehearsal reports the same id.
    pub(crate) checkpoint_id: String,
    /// Older backups deleted to honour `keep`.
    pub(crate) pruned: Vec<String>,
}

/// Takes one backup of `vault` and prunes older ones beyond `plan.keep`.
pub(crate) fn take(vault: &oneiron::Vault, plan: &BackupPlan) -> anyhow::Result<BackupOutcome> {
    create_private_dir(&plan.dir)?;
    let taken_ms = now_unix_ms();
    let stamp = file_stamp(taken_ms);
    let partial = plan
        .dir
        .join(format!(".{}-{stamp}{PARTIAL_SUFFIX}", plan.label));
    let checkpoint_id = match vault.snapshot_checkpoint(&partial, vault.now_recorded_at()) {
        Ok(id) => id,
        Err(error) => {
            let _ = std::fs::remove_file(&partial);
            return Err(anyhow::anyhow!("backup failed: {error}"));
        }
    };
    let id8 = checkpoint_id.get(..8).unwrap_or(&checkpoint_id);
    let file = format!("{}-{stamp}-{id8}{FILE_SUFFIX}", plan.label);
    let path = plan.dir.join(&file);
    std::fs::rename(&partial, &path)?;
    sync_dir(&plan.dir)?;
    let bytes = std::fs::metadata(&path)?.len();
    let pruned = prune(plan)?;
    Ok(BackupOutcome {
        backup: BackupRecord {
            file,
            path,
            bytes,
            taken: rfc3339(taken_ms),
            taken_ms,
        },
        checkpoint_id,
        pruned,
    })
}

/// This vault's backups, oldest first. A missing directory is no backups.
pub(crate) fn list(plan: &BackupPlan) -> anyhow::Result<Vec<BackupRecord>> {
    let entries = match std::fs::read_dir(&plan.dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let prefix = format!("{}-", plan.label);
    let mut records = Vec::new();
    for entry in entries {
        let entry = entry?;
        let file = entry.file_name().to_string_lossy().into_owned();
        // `<label>-<stamp>-<id8>.oneiron-backup`
        let Some(stamp) = file
            .strip_prefix(&prefix)
            .and_then(|rest| rest.strip_suffix(FILE_SUFFIX))
            .and_then(|rest| rest.rsplit_once('-'))
            .map(|(stamp, _)| stamp)
        else {
            continue;
        };
        let Some(taken_ms) = parse_file_stamp(stamp) else {
            continue;
        };
        let metadata = entry.metadata()?;
        if !metadata.is_file() {
            continue;
        }
        records.push(BackupRecord {
            path: entry.path(),
            file,
            bytes: metadata.len(),
            taken: rfc3339(taken_ms),
            taken_ms,
        });
    }
    records.sort_by(|a, b| (a.taken_ms, &a.file).cmp(&(b.taken_ms, &b.file)));
    Ok(records)
}

/// Deletes this vault's oldest backups beyond `plan.keep`; returns their names.
pub(crate) fn prune(plan: &BackupPlan) -> anyhow::Result<Vec<String>> {
    let records = list(plan)?;
    let excess = records.len().saturating_sub(plan.keep.max(1));
    let mut pruned = Vec::new();
    for record in records.into_iter().take(excess) {
        std::fs::remove_file(&record.path)?;
        pruned.push(record.file);
    }
    if !pruned.is_empty() {
        sync_dir(&plan.dir)?;
    }
    Ok(pruned)
}

/// What a rehearsal found in one backup.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Rehearsal {
    pub(crate) backup: PathBuf,
    pub(crate) checkpoint_id: String,
    /// The scratch vault the backup was restored into.
    pub(crate) restored_into: PathBuf,
    /// Whether that scratch vault was kept (`--scratch`) or deleted.
    pub(crate) kept: bool,
    /// Live entities in the restored copy, by kind.
    pub(crate) kinds: BTreeMap<String, u64>,
    pub(crate) entities: u64,
    pub(crate) text_documents: usize,
    pub(crate) pending_embeddings: usize,
    /// Doctor fields that did not decode in the restored copy; empty when sound.
    pub(crate) unreadable_fields: Vec<String>,
    pub(crate) verified: bool,
}

/// Restores `backup` into a scratch directory, opens it, checks it and
/// reports. The live vault is never opened. Without `keep_at`, the scratch
/// copy goes in the system temp directory and is deleted afterwards.
pub(crate) fn rehearse(
    backup: &Path,
    config: oneiron::VaultConfig,
    keep_at: Option<&Path>,
) -> anyhow::Result<Rehearsal> {
    let scratch = match keep_at {
        Some(path) => path.to_path_buf(),
        None => std::env::temp_dir().join(format!(
            "oneiron-rehearse-{}-{}",
            file_stamp(now_unix_ms()),
            std::process::id()
        )),
    };
    anyhow::ensure!(
        !scratch.exists(),
        "scratch directory {} already exists; name a new one",
        scratch.display()
    );
    let outcome = rehearse_into(backup, config, &scratch);
    // A failed rehearsal leaves nothing behind, even where it was told to keep.
    if keep_at.is_none() || outcome.is_err() {
        remove_scratch(&scratch);
    }
    let mut rehearsal = outcome?;
    rehearsal.kept = keep_at.is_some();
    Ok(rehearsal)
}

fn rehearse_into(
    backup: &Path,
    config: oneiron::VaultConfig,
    scratch: &Path,
) -> anyhow::Result<Rehearsal> {
    let (restored, report) = oneiron::Vault::restore_checkpoint(
        backup,
        scratch,
        config,
        RestoreReason::Restore,
        now_unix_ms() / 1_000,
    )
    .map_err(|error| anyhow::anyhow!("backup {} does not restore: {error}", backup.display()))?;
    let unreadable_fields = restored.doctor()?.unreadable_fields;
    let kinds = kind_counts(&restored)?;
    Ok(Rehearsal {
        backup: backup.to_path_buf(),
        checkpoint_id: report.epoch.checkpoint_id,
        restored_into: scratch.to_path_buf(),
        kept: false,
        entities: kinds.values().sum(),
        kinds,
        text_documents: report.rebuilt_text_documents,
        pending_embeddings: report.pending_embeddings,
        verified: unreadable_fields.is_empty(),
        unreadable_fields,
    })
}

/// Removes a scratch vault and the key-custody sibling an open may have made.
fn remove_scratch(scratch: &Path) {
    let _ = std::fs::remove_dir_all(scratch);
    if let Some(name) = scratch.file_name() {
        let mut keys = std::ffi::OsString::from(".");
        keys.push(name);
        keys.push(".gate-decision-keys");
        let _ = std::fs::remove_dir_all(scratch.with_file_name(keys));
    }
}

/// Live entity counts by registered kind, zero kinds omitted.
pub(crate) fn kind_counts(vault: &oneiron::Vault) -> anyhow::Result<BTreeMap<String, u64>> {
    let mut kinds = BTreeMap::new();
    for entry in oneiron::registry::ENTITY_TYPE_REGISTRY {
        let count = vault.count_entities_by_type(entry.type_byte)?;
        if count > 0 {
            kinds.insert(entry.kind.to_owned(), count);
        }
    }
    Ok(kinds)
}

/// What a real restore did.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Restored {
    pub(crate) backup: PathBuf,
    pub(crate) checkpoint_id: String,
    pub(crate) vault: PathBuf,
    /// The vault as it was before the restore, kept whole beside it.
    pub(crate) previous_vault: PathBuf,
    pub(crate) kinds: BTreeMap<String, u64>,
    pub(crate) entities: u64,
}

/// Restores `backup` over the stopped vault at `vault_path`.
///
/// Content comes from the backup; the vault's current authority (its log,
/// devices, slips, revocations and freshness pins) stays. The restored copy is
/// built beside the vault, and only then do the two directories swap. The old
/// vault is kept whole as `<vault>.pre-restore-<stamp>`; nothing is deleted.
pub(crate) fn restore_over(
    backup: &Path,
    vault_path: &Path,
    config: oneiron::VaultConfig,
) -> anyhow::Result<Restored> {
    anyhow::ensure!(
        vault_path.join("data.mdb").is_file(),
        "vault {} does not exist; nothing to restore over",
        vault_path.display()
    );
    let name = vault_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("vault path {} has no name", vault_path.display()))?
        .to_string_lossy()
        .into_owned();
    let stamp = file_stamp(now_unix_ms());
    let staging = vault_path.with_file_name(format!(".{name}.restore-{stamp}"));
    let previous = vault_path.with_file_name(format!("{name}.pre-restore-{stamp}"));
    anyhow::ensure!(
        !staging.exists() && !previous.exists(),
        "{} or {} already exists; try again",
        staging.display(),
        previous.display()
    );
    // Holding the writer lease keeps a server off the vault until the swap.
    let live =
        oneiron::Vault::open_owned(vault_path, config.clone()).map_err(|error| match error {
            oneiron::Error::ConcurrentWrite(oneiron::VAULT_WRITER_LEASE_HELD) => anyhow::anyhow!(
                "vault {} is open in a running `oneiron serve`; stop it before restoring",
                vault_path.display()
            ),
            error => anyhow::anyhow!("open vault {}: {error}", vault_path.display()),
        })?;
    let (restored, report) = match oneiron::Vault::restore_checkpoint_keeping_authority(
        backup,
        &staging,
        config.clone(),
        &live,
        live.now_recorded_at(),
    ) {
        Ok(restored) => restored,
        Err(error) => {
            remove_scratch(&staging);
            anyhow::bail!("backup {} does not restore: {error}", backup.display());
        }
    };
    drop(restored);
    std::fs::rename(vault_path, &previous)?;
    if let Err(error) = std::fs::rename(&staging, vault_path) {
        // Put the vault back where it was before reporting.
        let _ = std::fs::rename(&previous, vault_path);
        return Err(error.into());
    }
    if let Some(parent) = vault_path.parent() {
        sync_dir(parent)?;
    }
    drop(live);
    let reopened = oneiron::Vault::open_owned(vault_path, config)?;
    let kinds = kind_counts(&reopened)?;
    Ok(Restored {
        backup: backup.to_path_buf(),
        checkpoint_id: report.epoch.checkpoint_id,
        vault: vault_path.to_path_buf(),
        previous_vault: previous,
        entities: kinds.values().sum(),
        kinds,
    })
}

fn create_private_dir(dir: &Path) -> anyhow::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .map_err(|error| anyhow::anyhow!("create backup directory {}: {error}", dir.display()))
}

fn sync_dir(dir: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

#[cfg(test)]
mod tests;
