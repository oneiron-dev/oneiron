//! Local backups of one vault: take, list, prune, rehearse and restore.
//!
//! A backup is the engine's checkpoint image (`Vault::snapshot_checkpoint`):
//! canonical rows only, never indexes, never exterior key custody. Each one is
//! written under a hidden partial name and renamed into place, so a listing
//! never shows a half-written file. File names carry the vault's directory
//! name and a hash of its full path, so vaults sharing one backup directory
//! never list or prune each other's files, then a sequence number one past
//! the highest already there. Retention orders by that number, never by the
//! clock, so a clock that steps back cannot make a new backup look oldest.

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
        Self {
            dir,
            label: vault_label(vault_path),
            keep,
        }
    }
}

/// `<directory name>-<8 hex of the full path>`: readable, and distinct for two
/// vaults with one name in different places.
fn vault_label(vault_path: &Path) -> String {
    let name: String = vault_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "vault".to_owned())
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    // Resolve the parent, which exists whether or not the vault does yet.
    let full = vault_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .and_then(|parent| parent.canonicalize().ok())
        .zip(vault_path.file_name())
        .map(|(parent, file)| parent.join(file))
        .or_else(|| std::path::absolute(vault_path).ok())
        .unwrap_or_else(|| vault_path.to_path_buf());
    let hash = blake3::hash(full.as_os_str().as_encoded_bytes()).to_hex();
    format!("{name}-{}", &hash[..8])
}

/// One backup file.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct BackupRecord {
    pub(crate) file: String,
    pub(crate) path: PathBuf,
    /// Position among this vault's backups: each new one takes the next.
    pub(crate) sequence: u64,
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

/// Takes one backup of `vault` and prunes older ones beyond `plan.keep`. The
/// caller serializes backups of one vault (the writer lease, or the server's
/// backup lock), so the next sequence number is this one's alone.
pub(crate) fn take(vault: &oneiron::Vault, plan: &BackupPlan) -> anyhow::Result<BackupOutcome> {
    take_as(vault, plan, None)
}

/// [`take`] on an owner's request: the snapshot rechecks `owner` in its own
/// read transaction, so a request whose slip or ownership went away while it
/// waited writes and prunes nothing. The engine's refusal stays the error's
/// source.
pub(crate) fn take_as(
    vault: &oneiron::Vault,
    plan: &BackupPlan,
    owner: Option<&oneiron::consent::AuthenticatedOwner>,
) -> anyhow::Result<BackupOutcome> {
    create_private_dir(&plan.dir)?;
    let sequence = list(plan)?
        .last()
        .map_or(Some(1), |newest| newest.sequence.checked_add(1))
        .ok_or_else(|| anyhow::anyhow!("backup sequence exhausted in {}", plan.dir.display()))?;
    let taken_ms = now_unix_ms();
    let stamp = file_stamp(taken_ms);
    let partial = plan
        .dir
        .join(format!(".{}-{stamp}{PARTIAL_SUFFIX}", plan.label));
    let snapshot = match owner {
        Some(owner) => vault.snapshot_checkpoint_as(owner, &partial, vault.now_recorded_at()),
        None => vault.snapshot_checkpoint(&partial, vault.now_recorded_at()),
    };
    let checkpoint_id = match snapshot {
        Ok(id) => id,
        Err(error) => {
            let _ = std::fs::remove_file(&partial);
            return Err(anyhow::Error::new(error).context("backup failed"));
        }
    };
    let id8 = checkpoint_id.get(..8).unwrap_or(&checkpoint_id);
    let file = format!(
        "{}-{sequence:0SEQUENCE_WIDTH$}-{stamp}-{id8}{FILE_SUFFIX}",
        plan.label
    );
    let path = plan.dir.join(&file);
    std::fs::rename(&partial, &path)?;
    sync_dir(&plan.dir)?;
    let bytes = std::fs::metadata(&path)?.len();
    let pruned = prune(plan, &file)?;
    Ok(BackupOutcome {
        backup: BackupRecord {
            file,
            path,
            sequence,
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
        // `<label>-<sequence>-<stamp>-<id8>.oneiron-backup`. A backup named
        // before sequences, `<label>-<stamp>-<id8>`, lists as sequence 0:
        // older than every sequenced one.
        let Some((sequence, stamp)) = file
            .strip_prefix(&prefix)
            .and_then(|rest| rest.strip_suffix(FILE_SUFFIX))
            .and_then(|rest| rest.rsplit_once('-'))
            .map(|(rest, _)| rest.split_once('-').unwrap_or(("0", rest)))
        else {
            continue;
        };
        let (Some(sequence), Some(taken_ms)) = (parse_sequence(sequence), parse_file_stamp(stamp))
        else {
            continue;
        };
        // Retention may delete a file between the listing and this read.
        let metadata = match entry.metadata() {
            Ok(metadata) if metadata.is_file() => metadata,
            Ok(_) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        records.push(BackupRecord {
            path: entry.path(),
            file,
            sequence,
            bytes: metadata.len(),
            taken: rfc3339(taken_ms),
            taken_ms,
        });
    }
    records.sort_by(|a, b| (a.sequence, &a.file).cmp(&(b.sequence, &b.file)));
    Ok(records)
}

/// Digits a sequence number is padded to, so names also sort in order.
const SEQUENCE_WIDTH: usize = 10;

/// A sequence field `take` wrote: ASCII digits only.
fn parse_sequence(field: &str) -> Option<u64> {
    if field.is_empty() || !field.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    field.parse().ok()
}

/// Deletes this vault's oldest backups beyond `plan.keep`, never `spared` (the
/// backup a `take` just wrote, which counts as one kept); returns their names.
fn prune(plan: &BackupPlan, spared: &str) -> anyhow::Result<Vec<String>> {
    let records: Vec<_> = list(plan)?
        .into_iter()
        .filter(|record| record.file != spared)
        .collect();
    let excess = records.len().saturating_sub(plan.keep.max(1) - 1);
    let mut pruned = Vec::new();
    for record in records.into_iter().take(excess) {
        match std::fs::remove_file(&record.path) {
            Ok(()) => pruned.push(record.file),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
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
/// reports. The live vault is never opened. The copy is made in a directory
/// this call creates: `keep_at` names it and keeps it, otherwise it is a new
/// directory under the system temp directory and is deleted afterwards.
pub(crate) fn rehearse(
    backup: &Path,
    config: oneiron::VaultConfig,
    keep_at: Option<&Path>,
) -> anyhow::Result<Rehearsal> {
    let scratch = Owned::create(match keep_at {
        Some(path) => path.to_path_buf(),
        None => std::env::temp_dir().join(format!(
            "oneiron-rehearse-{}-{}",
            file_stamp(now_unix_ms()),
            oneiron::EntityId::now().to_hex()
        )),
    })?;
    let outcome = rehearse_into(backup, config, &scratch.vault());
    // A failed rehearsal leaves nothing behind, even where it was told to keep.
    if keep_at.is_none() || outcome.is_err() {
        scratch.remove();
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

/// A directory this call created, owner-only. A restored copy goes in its
/// `vault` subdirectory, so the copy and any key-custody sibling an open makes
/// beside it stay inside, and removing it removes only what this call made.
struct Owned {
    dir: PathBuf,
}

impl Owned {
    fn create(dir: PathBuf) -> anyhow::Result<Self> {
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(&dir)
            .map_err(|error| anyhow::anyhow!("create {}: {error}", dir.display()))?;
        Ok(Self { dir })
    }

    fn vault(&self) -> PathBuf {
        self.dir.join("vault")
    }

    fn remove(self) {
        let _ = std::fs::remove_dir_all(&self.dir);
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
    /// Set when the restore is in place but the directory holding it could
    /// not be synced: a crash before the filesystem flushes may undo the swap.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) durability_warning: Option<String>,
}

/// Restores `backup` over the stopped vault at `vault_path`.
///
/// Content comes from the backup; the vault's current authority (its log,
/// devices, slips, revocations and freshness pins) stays. The restored copy is
/// built in a staging directory beside the vault and swapped into its path in
/// one atomic exchange while this process holds the writer leases of both, so
/// no server opens either half-way. A filesystem that cannot exchange two
/// directories refuses the restore with nothing changed. The old vault is
/// kept whole as `<vault>.pre-restore-<stamp>`; nothing is deleted.
///
/// Once the swap is done the restore has happened, so a failed sync of the
/// directory after it is reported in `durability_warning`, never as an error
/// that would hide where the previous vault went.
pub(crate) fn restore_over(
    backup: &Path,
    vault_path: &Path,
    config: oneiron::VaultConfig,
) -> anyhow::Result<Restored> {
    restore_over_syncing(backup, vault_path, config, sync_dir)
}

fn restore_over_syncing(
    backup: &Path,
    vault_path: &Path,
    config: oneiron::VaultConfig,
    sync_after_swap: impl FnOnce(&Path) -> anyhow::Result<()>,
) -> anyhow::Result<Restored> {
    // Absolute from here on: a bare `vault` has an empty parent to sync.
    let vault_path = &std::path::absolute(vault_path)?;
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
    let previous = vault_path.with_file_name(format!("{name}.pre-restore-{stamp}"));
    anyhow::ensure!(
        !previous.exists(),
        "{} already exists; try again",
        previous.display()
    );
    let staging = Owned::create(vault_path.with_file_name(format!(".{name}.restore-{stamp}")))?;
    let live = match oneiron::Vault::open_owned(vault_path, config.clone()) {
        Ok(live) => live,
        Err(error) => {
            staging.remove();
            return Err(match error {
                oneiron::Error::ConcurrentWrite(oneiron::VAULT_WRITER_LEASE_HELD) => {
                    anyhow::anyhow!(
                        "vault {} is open in a running `oneiron serve`; stop it before restoring",
                        vault_path.display()
                    )
                }
                error => anyhow::anyhow!("open vault {}: {error}", vault_path.display()),
            });
        }
    };
    let restored_path = staging.vault();
    let (restored, report) = match oneiron::Vault::restore_checkpoint_keeping_authority(
        backup,
        &restored_path,
        config,
        &live,
        live.now_recorded_at(),
    ) {
        Ok(restored) => restored,
        Err(error) => {
            staging.remove();
            anyhow::bail!("backup {} does not restore: {error}", backup.display());
        }
    };
    let kinds = match kind_counts(&restored) {
        Ok(kinds) => kinds,
        Err(error) => {
            drop(restored);
            staging.remove();
            return Err(error);
        }
    };
    // One atomic exchange: the vault path never names nothing, and both
    // directories stay leased by this process until it is done.
    if let Err(error) = exchange(&restored_path, vault_path) {
        drop(restored);
        staging.remove();
        anyhow::bail!(
            "cannot swap the restored copy into {} atomically ({error}); nothing was changed",
            vault_path.display()
        );
    }
    // The old vault now sits inside the staging directory; give it its own
    // name. If that fails it stays where it is, whole, and is reported there.
    let previous = match std::fs::rename(&restored_path, &previous) {
        Ok(()) => {
            staging.remove();
            previous
        }
        Err(_) => restored_path,
    };
    let durability_warning = vault_path.parent().and_then(|parent| {
        let error = sync_after_swap(parent).err()?;
        tracing::warn!(
            error = %format!("{error:#}"),
            previous_vault = %previous.display(),
            "restore swapped in but the directory sync failed"
        );
        Some(format!(
            "the restore is in place, but {} could not be synced ({error:#}); a crash before \
             the filesystem flushes may undo it. The previous vault is {}",
            parent.display(),
            previous.display()
        ))
    });
    // Both leases are released only now, after the swap.
    drop(restored);
    drop(live);
    Ok(Restored {
        backup: backup.to_path_buf(),
        checkpoint_id: report.epoch.checkpoint_id,
        vault: vault_path.to_path_buf(),
        previous_vault: previous,
        entities: kinds.values().sum(),
        kinds,
        durability_warning,
    })
}

/// Atomically exchanges two directory entries.
fn exchange(a: &Path, b: &Path) -> std::io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::os::unix::ffi::OsStrExt;
        let a = std::ffi::CString::new(a.as_os_str().as_bytes())?;
        let b = std::ffi::CString::new(b.as_os_str().as_bytes())?;
        if exchange_raw(&a, &b) == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (a, b);
        Err(std::io::ErrorKind::Unsupported.into())
    }
}

#[cfg(target_os = "linux")]
fn exchange_raw(a: &std::ffi::CStr, b: &std::ffi::CStr) -> libc::c_int {
    // SAFETY: both pointers come from live NUL-terminated `CStr`s that outlive
    // the call; renameat2 only reads the two paths and writes no memory.
    unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            a.as_ptr(),
            libc::AT_FDCWD,
            b.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    }
}

#[cfg(target_os = "macos")]
fn exchange_raw(a: &std::ffi::CStr, b: &std::ffi::CStr) -> libc::c_int {
    // SAFETY: both pointers come from live NUL-terminated `CStr`s that outlive
    // the call; renamex_np only reads the two paths and writes no memory.
    unsafe { libc::renamex_np(a.as_ptr(), b.as_ptr(), libc::RENAME_SWAP) }
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
    // `Path::parent` of a one-component relative path is the empty path.
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

#[cfg(test)]
mod tests;
