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
//! stands none expires (ARCH-0038 #legal-hold). A label whose handoff policy
//! a managed setup installed keeps each backup until its node's supervisor
//! acks the stage copy (`handoff`).
//!
//! Once a backup lands, what it covered is recorded beside it
//! (`.<label>.backup-watermark.json`), so a host can tell whether the vault
//! changed since ([`oneiron::recovery::checkpoint::last_backed_up`]). A
//! backup asked for is always taken, changed or not.
//!
//! A restored vault is created sealed (OF-570 maximum tier) by one rule,
//! [`restore_target_seal`]: over a vault or beside it, at that vault's tier;
//! where no vault is, at the tier the config asks for. Re-sealing is a new
//! sealed vault and a row-level copy, never a converter.
//!
//! The vault's exterior key custody publishes beside the backups instead, as
//! a sealed, recovery-wrapped custody head and keyless log (`custody`,
//! KS-4A1); a restore on a host without that custody recovers it from there.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[cfg(test)]
use oneiron::recovery::checkpoint::SideRestoreSource;
use serde::Serialize;

#[cfg(test)]
use super::stamp::file_stamp;
use super::stamp::{parse_file_stamp, rfc3339};
use crate::machine::DiskFloor;

mod checkpoint_fact;
mod custody;
pub(crate) mod finalize;
mod handoff;
mod rehearse;
mod relay_hold;
mod restore;
mod scratch;
pub(crate) mod write_budget;

pub(crate) use self::custody::{
    CustodyAnchorCredentials, custody_recovery, custody_status, take_publishing,
};
#[cfg(test)]
use self::rehearse::Owned;
#[cfg(test)]
pub(crate) use self::rehearse::rehearse_in;
use self::rehearse::rehearse_in_with;
pub(crate) use self::rehearse::{Rehearsal, rehearse, rehearse_keyed};
pub(crate) use self::relay_hold::VaultRelayHoldGuard;
pub(crate) use self::restore::{
    RestoreTarget, RestoredFresh, activate, restore_fresh, restore_over, restore_over_keyed,
    restore_target_seal,
};
#[cfg(test)]
use self::restore::{exchange, restore_over_syncing};
#[cfg(unix)]
pub(crate) use self::scratch::sweep_rehearsals;

const FILE_SUFFIX: &str = ".oneiron-backup";
const PARTIAL_SUFFIX: &str = ".partial";

/// Where one vault's backups live and how many are kept.
#[derive(Clone, Debug)]
pub(crate) struct BackupPlan {
    pub(crate) dir: PathBuf,
    /// File-name prefix scoping listing and pruning to this vault.
    pub(crate) label: String,
    pub(crate) keep: usize,
    /// Where the vault's custody anchors and which hosted members it names
    /// (`custody`): unset by default, the anchor step pending by name.
    pub(crate) custody: custody::CustodyPlan,
    /// The free-space floor a serving host keeps under its uploads, lent so
    /// this vault's backups and rehearsals claim their writes on it
    /// ([`write_budget`], FIX 5479); `None` on a stopped vault.
    floor: Option<DiskFloor>,
    /// The registry's id for this vault, which each backup binds its vault id
    /// to (FIX 5826): a managed vault's name. `None` where this host knows
    /// none (plain serve, the stopped CLI), and the backup says so; nothing
    /// is refused either way, and nothing of it is kept.
    pub(crate) registry: Option<String>,
    /// When this label's handoff backlog last raised its check (`handoff`).
    backlog_checked: handoff::BacklogChecked,
    /// Pruning past `keep` is held and every backup is kept: a managed
    /// vault whose backup handoff policy could not be installed (FIX 6705).
    pub(crate) prune_held: bool,
}

impl BackupPlan {
    pub(crate) fn new(vault_path: &Path, dir: PathBuf, keep: usize) -> Self {
        Self {
            dir,
            label: vault_label(vault_path),
            keep,
            custody: custody::CustodyPlan::default(),
            floor: None,
            registry: None,
            backlog_checked: handoff::BacklogChecked::default(),
            prune_held: false,
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
    /// Why a hosted vault's backup carries none of its host-order legal
    /// holds, for its host to alert on (FIX 6598); absent where it carries
    /// them or the vault is self-hosted. Nothing of any hold.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) host_holds_unavailable: Option<oneiron::recovery::checkpoint::HostHoldsUnavailable>,
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
    let produced =
        finalize::produce(vault, plan, owner).map_err(finalize::Unproduced::into_error)?;
    // What it covered, beside it now that it landed. A marker that fails
    // leaves the one before, which only reads as changed.
    if let Err(error) = produced.accept(plan) {
        tracing::warn!(
            reason = "backup_watermark_marker_failed",
            error = %error,
            "the backup landed; what it covered was not recorded, so the next check reads changed"
        );
    }
    // FIX 9522: with an HTTP anchor this stages custody locally and returns; the
    // background publisher does the anchor reads and advances.
    custody::publish_after_take(vault, plan);
    let bytes = std::fs::metadata(&produced.path)?.len();
    let pruned = prune(vault, plan, Some(&produced.file))?;
    Ok(produced.into_outcome(bytes, pruned))
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

/// [`list`], and the backups among them a managed handoff pin keeps pending
/// for a stage ack (FIX 6335), oldest first: retention's excess past `keep`
/// whose ack does not name the file held here. The pin still keeps every one.
pub(crate) fn list_with_pending(
    plan: &BackupPlan,
) -> anyhow::Result<(Vec<BackupRecord>, Vec<BackupRecord>)> {
    let records = list(plan)?;
    let pending = handoff::handoff_pending(plan, &records);
    Ok((records, pending))
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

/// Deletes this vault's oldest backups beyond `plan.keep`; returns their
/// names. `spared`, the backup a `take` just wrote, is never deleted and
/// counts as one kept; with none spared, the newest `keep` stay. Nothing
/// goes while a legal hold stands: the listing and acks are read first, then
/// the holds are read and each unlink and directory sync runs while the
/// vault's writer is held ([`oneiron::Vault::with_backup_hold_exclusion`]),
/// so a hold placed meanwhile commits before the read or after the sync
/// (FIX 1488). A label whose handoff policy is installed deletes only the
/// ones its node's supervisor acked, and keeps the rest pending, an error
/// included (`handoff`). The caller holds the backup lock.
pub(crate) fn prune(
    vault: &oneiron::Vault,
    plan: &BackupPlan,
    spared: Option<&str>,
) -> anyhow::Result<Vec<String>> {
    // A standing hold keeps them all; the exclusion below reads it again. So
    // does a held prune (FIX 6705).
    if plan.prune_held || vault.legal_hold_keeps_backups()? {
        return Ok(Vec::new());
    }
    checkpoint_fact::sweep(vault, plan);
    // FIX 7607: stage acks whose artifact is gone go with the prune; pinned
    // acks whose artifact exists stay.
    handoff::sweep_orphan_stage_acks(plan);
    let records: Vec<_> = list(plan)?
        .into_iter()
        .filter(|record| Some(record.file.as_str()) != spared)
        .collect();
    let keep = plan.keep.max(1) - usize::from(spared.is_some());
    let excess = records.len().saturating_sub(keep);
    let excess: Vec<_> = records.into_iter().take(excess).collect();
    let Some(handoff) = handoff::pinned(&plan.dir, &plan.label) else {
        let gone = vault.with_backup_hold_exclusion(|holds| -> anyhow::Result<Vec<String>> {
            let mut pruned = Vec::new();
            if holds.keeps_backups() {
                return Ok(pruned);
            }
            for record in excess {
                match std::fs::remove_file(&record.path) {
                    Ok(()) => {
                        checkpoint_fact::remove(&plan.dir, &record.file);
                        pruned.push(record.file);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if !pruned.is_empty() {
                sync_dir(&plan.dir)?;
            }
            Ok(pruned)
        })??;
        // Each unlink is synced: only now does its local holder go, the one
        // copy this host kept (FIX 6022, 7060). A handed-off copy's
        // supervisor holds its own, which no ack here releases.
        for file in &gone {
            if let Err(error) = vault.release_backup_copy(&plan.dir.join(file)) {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a pruned backup's body holder was not released; its bodies stay kept"
                );
            }
        }
        return Ok(gone);
    };
    let (released, mut pending) = handoff::released(&handoff, &plan.label, excess);
    let pruned = vault.with_backup_hold_exclusion(|holds| {
        if holds.keeps_backups() {
            return None;
        }
        let mut pruned = Vec::new();
        for (record, ack) in released {
            match std::fs::remove_file(&record.path) {
                Ok(()) => {
                    checkpoint_fact::remove(&plan.dir, &record.file);
                    let _ = std::fs::remove_file(ack);
                    pruned.push(record.file);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                // Kept, and pending: a pinned backup is never lost to an error.
                Err(_) => pending.push(record),
            }
        }
        if !pruned.is_empty() {
            let _ = sync_dir(&plan.dir).and_then(|()| sync_dir(&handoff));
        }
        Some(pruned)
    })?;
    // A standing hold keeps them all, acked or not.
    let Some(pruned) = pruned else {
        return Ok(Vec::new());
    };
    handoff::check_backlog(vault, &plan.backlog_checked, &pending);
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

/// Syncs `dir` through the engine's one portable flush (FIX 7060), on every
/// platform, before anything an unlink released is let go.
fn sync_dir(dir: &Path) -> anyhow::Result<()> {
    // `Path::parent` of a one-component relative path is the empty path.
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    oneiron::store::sync_dir(dir)?;
    Ok(())
}

#[cfg(test)]
mod tests;
