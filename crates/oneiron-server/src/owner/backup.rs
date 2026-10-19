//! Local backups of one vault: take, list, prune, rehearse and restore.
//!
//! A backup is the engine's checkpoint image (`Vault::snapshot_backup`):
//! canonical rows only, never indexes, never exterior key custody, sealed with
//! the result bodies its rows name into one artifact under a key derived from
//! the vault data key. The first backup mints that key, wrapped to this
//! device, when the vault has none; a rehearsal or restore on this device
//! unlocks it from the device wrap the backup carries, and one on a host
//! without that wrap from the password, passkey or escrow wrap it carries,
//! trusting the signers the owner pinned. A restore where no vault is yet
//! makes the vault there. Each one is
//! written under a hidden partial name and renamed into place, so a listing
//! never shows a half-written file. File names carry the vault's directory
//! name and a hash of its full path, so vaults sharing one backup directory
//! never list or prune each other's files, then a sequence number one past
//! the highest already there. Retention orders by that number, never by the
//! clock, so a clock that steps back cannot make a new backup look oldest.
//! A backup holds every record its image carries, so while any legal hold
//! stands none expires (ARCH-0038 #legal-hold).
//!
//! A restored vault is created sealed (OF-570 maximum tier) by one rule,
//! [`restore_target_seal`]: over a vault or beside it, at that vault's tier;
//! where no vault is, at the tier the config asks for. Re-sealing is a new
//! sealed vault and a row-level copy, never a converter.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[cfg(test)]
use oneiron::recovery::checkpoint::SideRestoreSource;
use serde::Serialize;

use super::stamp::{file_stamp, now_unix_ms, parse_file_stamp, rfc3339};
use crate::machine::DiskFloor;

mod rehearse;
mod restore;
pub(crate) mod write_budget;

#[cfg(test)]
use self::rehearse::Owned;
#[cfg(test)]
pub(crate) use self::rehearse::rehearse_in;
use self::rehearse::rehearse_in_with;
pub(crate) use self::rehearse::{Rehearsal, rehearse, rehearse_keyed};
pub(crate) use self::restore::{
    RestoreTarget, RestoredFresh, activate, restore_fresh, restore_over, restore_over_keyed,
    restore_target_seal,
};
#[cfg(test)]
use self::restore::{exchange, restore_over_syncing};

const FILE_SUFFIX: &str = ".oneiron-backup";
const PARTIAL_SUFFIX: &str = ".partial";

/// Where one vault's backups live and how many are kept.
#[derive(Clone, Debug)]
pub(crate) struct BackupPlan {
    pub(crate) dir: PathBuf,
    /// File-name prefix scoping listing and pruning to this vault.
    pub(crate) label: String,
    pub(crate) keep: usize,
    /// The free-space floor a serving host keeps under its uploads, lent so
    /// this vault's backups and rehearsals claim their writes on it
    /// ([`write_budget`], FIX 5479); `None` on a stopped vault.
    floor: Option<DiskFloor>,
}

impl BackupPlan {
    pub(crate) fn new(vault_path: &Path, dir: PathBuf, keep: usize) -> Self {
        Self {
            dir,
            label: vault_label(vault_path),
            keep,
            floor: None,
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
    /// Older backups deleted to honour `keep`; none while a legal hold stands.
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
    // The artifact claims its room on the floor the plan was lent, and gives
    // it back once written or refused (FIX 5479).
    let snapshot = vault.ensure_vault_key().and_then(|()| {
        let room = write_budget::WriteClaim::on(plan.floor.as_ref());
        vault.snapshot_backup_within(&partial, vault.now_recorded_at(), owner, &room)
    });
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
    let pruned = if vault.legal_hold_keeps_backups()? {
        Vec::new()
    } else {
        prune(plan, &file)?
    };
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
    builder.create(dir).map_err(|error| {
        anyhow::Error::new(error).context(format!("create backup directory {}", dir.display()))
    })
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
