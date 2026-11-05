//! Restores of one vault's backups: over the stopped vault, where no vault
//! is yet, and the activation of the vault a restore set aside (moved out of
//! `backup` whole).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use oneiron::VaultPageSeal;
use oneiron::recovery::checkpoint::{
    CheckpointKey, CustodyRecovery, HostOrderHolds, SideRestoreSource,
};
use oneiron::world_keys::{
    page_seal_custody_path, page_seal_incarnations, unlock_page_seal, vault_is_sealed,
};
use oneiron_vault_contract::backup_handoff::write_private_file;
use serde::Serialize;

use super::super::stamp::{file_stamp, now_unix_ms, parse_file_stamp};
use super::rehearse::{Owned, SharedPathWarning, shared_path_warning};
use super::{kind_counts, sync_dir};

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
    /// What the restore costs the vault's publisher training: set when it
    /// brought no training link key (FIX 5892).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) training_note: Option<String>,
    /// The home tables the restore took from the image because the live
    /// vault's rows did not read (FIX 5661 C2b).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) home_table_notes: Vec<String>,
    /// The world key pads the restore did not land at rest (KS-5): erased
    /// since the backup, withheld by their world's sealed copies setting, or
    /// pending as in the vault it replaced.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) pad_notes: Vec<String>,
    /// The credential values the restore did not land readable (KS-6), by
    /// handle and generation, each with its remedy.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) credential_notes: Vec<String>,
    /// What the restore did not carry of its source's current pad objects
    /// (PAD-1), each as the engine words it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) pad_object_notes: Vec<String>,
    /// Outcomes for staging directories earlier interrupted restores left
    /// beside this vault (FIX 2706): each is claimed as a pre-restore archive
    /// or left whole where it is, with the outcome named here.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) staging_notes: Vec<String>,
}

/// Restores `backup` over the stopped vault at `vault_path`.
///
/// Content comes from the backup; the vault's current authority (its log,
/// devices, slips, revocations and freshness pins) and key custody stay. The
/// restored copy is built in a staging directory beside the vault and swapped
/// into its path in one atomic exchange while this process holds the writer
/// leases of both, so no server opens either half-way. A filesystem that
/// cannot exchange two directories refuses the restore with nothing changed.
/// The old vault is kept whole as `<vault>.pre-restore-<stamp>`; nothing is
/// deleted. It still binds the key custody the restored vault keeps, so it is
/// archived: it opens and reads, and refuses every write, erase and key
/// retirement until `oneiron restore --activate` gives it custody of its own.
///
/// Once the swap is done the restore has happened, so a failed sync of the
/// directory after it is reported in `durability_warning`, never as an error
/// that would hide where the previous vault went.
///
/// The backup opens with `keystore`, the install's configured one; with
/// none it refuses, naming the platform backend (FIX 12225).
pub(crate) fn restore_over(
    backup: &Path,
    vault_path: &Path,
    config: oneiron::VaultConfig,
    keystore: Option<Arc<dyn oneiron_keystore::DeviceKeystore>>,
) -> anyhow::Result<Restored> {
    restore_over_syncing(backup, vault_path, config, keystore, exchange, sync_dir)
}

/// [`restore_over`] with a key the caller unlocked from another wrap the
/// backup carries and pinned to the signers it trusts.
pub(crate) fn restore_over_keyed(
    backup: &Path,
    vault_path: &Path,
    config: oneiron::VaultConfig,
    key: CheckpointKey,
) -> anyhow::Result<Restored> {
    // Only a checkpoint key, no vault-key unlock: sealed staging stays
    // report-only (FIX 2706).
    restore_over_with(
        backup,
        vault_path,
        config,
        None,
        |_| Ok(key),
        exchange,
        sync_dir,
    )
}

pub(super) fn restore_over_syncing(
    backup: &Path,
    vault_path: &Path,
    config: oneiron::VaultConfig,
    keystore: Option<Arc<dyn oneiron_keystore::DeviceKeystore>>,
    swap: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
    sync_after_swap: impl FnOnce(&Path) -> anyhow::Result<()>,
) -> anyhow::Result<Restored> {
    // This install's keystore unlocks the key from the device wrap the backup
    // carries, and trusts the signers it holds; with none it refuses (FIX 12225).
    let open_key =
        |_vault_path: &Path| CheckpointKey::unlock_on_this_device(backup, keystore.as_ref());
    // The same keystore probes sealed staging earlier restores left (FIX 2706).
    let staging_unlock = keystore
        .as_ref()
        .map(|keystore| oneiron::world_keys::VaultKeyUnlock::Device(keystore.as_ref()));
    restore_over_with(
        backup,
        vault_path,
        config,
        staging_unlock.as_ref(),
        |vault_path| open_key(vault_path).map_err(anyhow::Error::from),
        swap,
        sync_after_swap,
    )
}

fn restore_over_with(
    backup: &Path,
    vault_path: &Path,
    config: oneiron::VaultConfig,
    staging_unlock: Option<&oneiron::world_keys::VaultKeyUnlock>,
    open_key: impl FnOnce(&Path) -> anyhow::Result<CheckpointKey>,
    swap: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
    sync_after_swap: impl FnOnce(&Path) -> anyhow::Result<()>,
) -> anyhow::Result<Restored> {
    // Absolute from here on: a bare `vault` has an empty parent to sync.
    let configured = std::path::absolute(vault_path)?;
    anyhow::ensure!(
        configured.join("data.mdb").is_file(),
        "vault {} does not exist; nothing to restore over",
        configured.display()
    );
    // Before anything is made or opened: no other user may move an entry on
    // the way to the vault, or in it, or the names below could change.
    #[cfg(unix)]
    oneiron::store::refuse_shared_vault_root(&configured)?;
    // The directory itself, not a symlink to it: the exchange below must move
    // the very directory the vault opens from, which the archive marks name.
    let vault_path = &configured.canonicalize()?;
    let name = vault_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("vault path {} has no name", vault_path.display()))?
        .to_string_lossy()
        .into_owned();
    // Earlier interrupted restores left their staging beside the vault; list
    // it before this restore makes its own (FIX 2706).
    let staged = interrupted_restore_staging(vault_path, &name);
    // The backup opens before anything is made.
    let key = open_key(vault_path.as_path())
        .map_err(|error| anyhow::anyhow!("backup {} does not open: {error:#}", backup.display()))?;
    // A sealed previous vault a crash left in staging is claimed as its
    // archive now, after the backup opened and before either vault is held:
    // the probes refuse while this process holds the env (FIX 2705).
    let staging_notes: Vec<String> = staged
        .into_iter()
        .map(|(_, stamp_text, staging)| {
            claim_staged_archive(vault_path, &name, &stamp_text, &staging, staging_unlock)
        })
        .collect();
    let stamp = file_stamp(now_unix_ms());
    let previous = vault_path.with_file_name(format!("{name}.pre-restore-{stamp}"));
    anyhow::ensure!(
        !previous.exists(),
        "{} already exists; try again",
        previous.display()
    );
    // The live vault opens with its own seal; the copy is created under a
    // fresh incarnation of it, and so keeps its tier.
    let mut target = config.clone();
    target.page_seal = restore_target_seal(RestoreTarget::Beside(config.page_seal.as_ref()))?;
    // The original restore holds the same per-staging claim lock from before
    // its staging becomes visible through archive publication, rename and
    // cleanup (round-2 P1): a claimant that scans this staging takes the
    // lock only once this restore is done with it, and otherwise leaves the
    // staging and archive mirrors untouched.
    let Some(parent) = vault_path.parent() else {
        anyhow::bail!("vault path {} has no parent", vault_path.display());
    };
    let claim_guard = match take_staging_claim_lock(parent, &name, &stamp) {
        Some(guard) => guard,
        None => {
            anyhow::bail!(
                "the staging claim for {} is already held; try again",
                vault_path.display()
            );
        }
    };
    let staging = Owned::create(vault_path.with_file_name(format!(".{name}.restore-{stamp}")))?;
    let live = match oneiron::Vault::open_owned(vault_path, config) {
        Ok(live) => live,
        Err(error) => {
            staging.remove();
            claim_guard.release();
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
    // The copy replaces the vault at its path, so it keeps the vault's key custody.
    let (restored, report) = match oneiron::Vault::restore_checkpoint_replacing(
        backup,
        &key,
        &restored_path,
        target,
        &live,
        live.now_recorded_at(),
    ) {
        Ok(restored) => restored,
        Err(error) => {
            staging.remove();
            claim_guard.release();
            anyhow::bail!("backup {} does not restore: {error}", backup.display());
        }
    };
    let kinds = match kind_counts(&restored) {
        Ok(kinds) => kinds,
        Err(error) => {
            drop(restored);
            staging.remove();
            claim_guard.release();
            return Err(error);
        }
    };
    // A sealed vault's mirror sits beside its directory and stays put in the
    // exchange: until the swap is confirmed, the mirrors beside both name
    // both incarnations, so each environment opens wherever it ends up.
    let sealed_swap = match live.stage_sealed_swap(&restored) {
        Ok(sealed_swap) => sealed_swap,
        Err(error) => {
            drop(restored);
            staging.remove();
            claim_guard.release();
            anyhow::bail!("the restored copy's page-seal mirrors were not staged: {error}");
        }
    };
    // One atomic exchange: the vault path never names nothing, and both
    // directories stay leased by this process until it is done. The old
    // vault still binds the key custody the restored copy now holds, so the
    // engine archives it with the swap: whichever of the two sits at the
    // vault path is the live one, even after a crash in the middle, and the
    // other reads but never writes, erases or shreds a key until the owner
    // activates it as a side vault with custody of its own.
    let exchanged = std::cell::Cell::new(false);
    if let Err(error) = live.swap_in_replacement(&restored, || {
        swap(&restored_path, vault_path)?;
        exchanged.set(true);
        Ok(())
    }) {
        drop(restored);
        // Once the directories were exchanged, both stay where they are: the
        // marks keep whichever sits at the vault path live, and the staging
        // directory may hold the previous vault.
        if exchanged.get() {
            anyhow::bail!(
                "the restored copy was exchanged with {}, but the swap could not be confirmed \
                 ({error}); nothing was removed: the other vault is at {}, and the one at {} is \
                 the live one",
                vault_path.display(),
                restored_path.display(),
                vault_path.display()
            );
        }
        staging.remove();
        claim_guard.release();
        anyhow::bail!(
            "cannot swap the restored copy into {} ({error}); nothing was moved, and the vault \
             there stays live only at that path",
            vault_path.display()
        );
    }
    // The old vault now sits inside the staging directory; give it its own
    // name, a sealed one with its mirror beside that name first. If that
    // fails it stays where it is, whole, beside the mirror that opens it
    // there, and is reported there.
    let named = match &sealed_swap {
        Some(sealed_swap) => sealed_swap
            .mirror_archive(&previous)
            .map_err(|error| std::io::Error::other(error.to_string())),
        None => Ok(()),
    }
    .and_then(|()| std::fs::rename(&restored_path, &previous));
    let previous = match named {
        Ok(()) => {
            staging.remove();
            claim_guard.release();
            previous
        }
        Err(_) => {
            if let Some(sealed_swap) = &sealed_swap {
                sealed_swap.discard_archive_mirror(&previous);
            }
            restored_path
        }
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
    // The swap is durable: the vault's mirror names the restored incarnation
    // alone. Until then, or should this fail, it names both, and the next
    // open of the vault takes the one that opens it.
    if durability_warning.is_none()
        && let Some(sealed_swap) = &sealed_swap
        && let Err(error) = sealed_swap.confirm(vault_path)
    {
        tracing::warn!(
            %error,
            "the restored vault's page-seal mirror still names both incarnations"
        );
    }
    // Both leases are released only now, after the swap.
    drop(restored);
    drop(live);
    Ok(Restored {
        backup: backup.to_path_buf(),
        checkpoint_id: report.epoch.checkpoint_id,
        vault: configured,
        previous_vault: previous,
        entities: kinds.values().sum(),
        kinds,
        durability_warning,
        training_note: report.training_note,
        home_table_notes: report
            .home_table_notes
            .iter()
            .map(ToString::to_string)
            .collect(),
        pad_notes: report.pad_notes.iter().map(ToString::to_string).collect(),
        credential_notes: report
            .credential_notes
            .iter()
            .map(ToString::to_string)
            .collect(),
        pad_object_notes: report
            .pad_object_notes
            .iter()
            .map(ToString::to_string)
            .collect(),
        staging_notes,
    })
}

/// The staging directories earlier interrupted restores of this vault left
/// beside it (FIX 2706), oldest first, each as its stamp in ms, its stamp
/// text and its path. A restore that dies mid-flight leaves
/// `.<name>.restore-<stamp>` holding a whole vault: before its atomic
/// exchange that is the restored copy, after it the previous vault, its
/// archive rename never run. The scan never fails the restore that lists it.
/// Each hit is claimed or left whole by [`claim_staged_archive`], which names
/// it in `staging_notes` so it is not lost track of.
fn interrupted_restore_staging(vault_path: &Path, name: &str) -> Vec<(u64, String, PathBuf)> {
    let Some(parent) = vault_path.parent() else {
        return Vec::new();
    };
    let entries = match std::fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) => {
            tracing::warn!(
                %error,
                parent = %parent.display(),
                "could not look for staging left by an interrupted restore"
            );
            return Vec::new();
        }
    };
    let prefix = format!(".{name}.restore-");
    let mut found: Vec<(u64, String, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        let Some(stamp) = file_name.strip_prefix(&prefix) else {
            continue;
        };
        let Some(stamp_ms) = parse_file_stamp(stamp) else {
            continue;
        };
        // The staging directory itself, never a symlink to one.
        if !matches!(entry.file_type(), Ok(kind) if kind.is_dir()) {
            continue;
        }
        found.push((stamp_ms, stamp.to_owned(), entry.path()));
    }
    found.sort_unstable();
    found
}

/// Cross-process claim lock for one leftover staging directory (round-1 P1
/// on #4518): two restores reaching the same staging take it in turn, and
/// the contender leaves the staging and archive mirrors untouched instead
/// of deleting the winner's archive mirror on its failed rename. The lock
/// file stays while the staging directory may still exist, so every taker
/// meets the same inode (unlinking on drop would let a contender lock a
/// fresh inode while the winner still holds the old one); the held-open
/// file (and its flock on unix) lasts until the guard drops.
struct StagingClaimGuard {
    _held: std::fs::File,
    path: PathBuf,
}

impl StagingClaimGuard {
    /// Unlinks the lock file; call only once the staging directory is gone,
    /// so no later taker can meet a live staging under a fresh inode.
    fn release(self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Opens (creating) the claim-lock file for one leftover staging directory
/// and takes it nonblocking-exclusive. `None` means the claim is already
/// held: the caller leaves the staging and archive mirrors untouched. On
/// unix the flock releases if the holder dies, so no stale lock survives a
/// crash; elsewhere the create is exclusive and the file stays until the
/// staging is gone and the holder releases it.
fn take_staging_claim_lock(
    parent: &Path,
    name: &str,
    stamp_text: &str,
) -> Option<StagingClaimGuard> {
    let path = parent.join(format!(".{name}.restore-{stamp_text}.claim-lock"));
    #[cfg(unix)]
    {
        use rustix::fs::{FlockOperation, Mode, OFlags};
        let held = std::fs::File::from(
            rustix::fs::open(
                &path,
                OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .ok()?,
        );
        match rustix::fs::flock(&held, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Some(StagingClaimGuard { _held: held, path }),
            // A contender holds it: leave the mirrors untouched.
            Err(_) => None,
        }
    }
    #[cfg(not(unix))]
    {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(held) => Some(StagingClaimGuard { _held: held, path }),
            Err(_) => None,
        }
    }
}

/// Claims the staging directory `staging` (stamp `stamp_text`) an earlier
/// interrupted restore of the vault at `vault_path` left, as the archive name
/// that restore never reached, or leaves it whole where it is (FIX 2706).
/// Shape (a) only: a sealed vault whose home and staged mirrors each name the
/// opened incarnation second ((1, 1)) holds its previous vault in staging, and
/// that vault is renamed to `<name>.pre-restore-<stamp>` with its stamp. A
/// pre-swap copy ((0, 0)), a torn or ambiguous pair, a plain vault (no
/// universal discriminator), a sealed vault with no unlock to probe it, and
/// anything that fails along the way stays whole and is reported as left: the
/// scan and the claim never fail the restore, add no refusal, hold or wait,
/// and remove nothing but the staging mirror and directory of a claim that
/// landed (and its own claim-lock file). Two restores reaching the same
/// leftover staging take the cross-process claim lock in turn; the contender
/// leaves the staging and archive mirrors untouched. Returns the
/// `staging_notes` line for the staging directory.
fn claim_staged_archive(
    vault_path: &Path,
    name: &str,
    stamp_text: &str,
    staging: &Path,
    unlock: Option<&oneiron::world_keys::VaultKeyUnlock>,
) -> String {
    let staged_vault = staging.join("vault");
    // Without a whole vault there is nothing to claim.
    if !staged_vault.join("data.mdb").is_file() {
        let note = format!(
            "an earlier interrupted restore left its staging directory {} \
             without a whole vault in it; the staging directory is left \
             where it is",
            staging.display()
        );
        tracing::warn!(staging = %staging.display(), "{note}");
        return note;
    }
    // A whole vault left where it is, as Pack1 reports it.
    let left_whole = || {
        let note = format!(
            "an earlier interrupted restore left a whole vault in its staging \
             directory {}; the vault at {} is the live one, and the staged one \
             is left whole where it is",
            staging.display(),
            vault_path.display()
        );
        tracing::warn!(staging = %staging.display(), "{note}");
        note
    };
    // Plain vaults stay undecidable and report-only: no universal
    // discriminator names which environment is the previous one.
    let sealed = match vault_is_sealed(vault_path) {
        Ok(sealed) => sealed,
        Err(_) => return left_whole(),
    };
    if !sealed {
        return left_whole();
    }
    // Sealed with no unlock (a keyed restore, a keystore that is off) cannot
    // be probed, so it stays report-only.
    let Some(unlock) = unlock else {
        return left_whole();
    };
    // Shape (a): the index of the incarnation that opens each side in the
    // mirror beside it. Only (1, 1) claims; (0, 0) is a pre-swap copy and
    // anything else, including a probe that does not open, is torn and stays.
    let mirror_index = |path: &Path| -> Option<(usize, VaultPageSeal)> {
        let seal = unlock_page_seal(path, unlock).ok()?;
        let named = page_seal_incarnations(path).ok()?;
        let index = named
            .iter()
            .position(|candidate| *candidate == seal.incarnation())?;
        Some((index, seal))
    };
    let home = mirror_index(vault_path).map(|(index, _)| index);
    let staged = mirror_index(&staged_vault);
    let previous_seal = match (home, staged) {
        (Some(1), Some((1, seal))) => seal,
        _ => return left_whole(),
    };
    let Some(parent) = vault_path.parent() else {
        return left_whole();
    };
    // The cross-process claim lock (round-1 P1 on #4518): two restores that
    // reach the same leftover staging take it in turn, and the contender
    // leaves the staging and archive mirrors untouched instead of deleting
    // the winner's archive mirror on its failed rename.
    let claim_guard = match take_staging_claim_lock(parent, name, stamp_text) {
        Some(guard) => guard,
        None => {
            let note = format!(
                "the staging directory {} is already claimed by another                  restore, so the staging and archive mirrors are left untouched",
                staging.display()
            );
            tracing::warn!(staging = %staging.display(), "{note}");
            return note;
        }
    };
    let archive = parent.join(format!("{name}.pre-restore-{stamp_text}"));
    // Never overwrite: any name in the way leaves the staging whole.
    if std::fs::symlink_metadata(&archive).is_ok() {
        tracing::warn!(
            staging = %staging.display(),
            archive = %archive.display(),
            "the archive name is taken; the staged vault is left whole where it is"
        );
        return left_whole();
    }
    let archive_mirror = match page_seal_custody_path(&archive) {
        Ok(path) => path,
        Err(_) => return left_whole(),
    };
    // `write_private_file` renames over, so the mirror name must be free too.
    if std::fs::symlink_metadata(&archive_mirror).is_ok() {
        tracing::warn!(
            staging = %staging.display(),
            archive = %archive.display(),
            "the archive mirror name is taken; the staged vault is left whole where it is"
        );
        return left_whole();
    }
    let staged_mirror = match page_seal_custody_path(&staged_vault) {
        Ok(path) => path,
        Err(_) => return left_whole(),
    };
    let mirror_bytes = match std::fs::read(&staged_mirror) {
        Ok(bytes) => bytes,
        Err(_) => return left_whole(),
    };
    // The archive mirror copies the staging mirror's bytes, never the home
    // mirror's: after a rename-failed-then-confirmed run the home mirror is
    // narrowed to the restored incarnation alone while the staging mirror
    // still names both. A both-naming archive mirror is an engine-tolerated
    // mid-protocol state ("A crash between any two steps leaves each
    // environment beside a mirror that names its incarnation... its next
    // mirror rewrite names that one alone"): the archive opens under the
    // previous incarnation. After the rename the finisher below names that
    // one alone; if it fails, the archive's first open still narrows it.
    // This assumes the carried wraps, the replacement's, still open
    // the previous vault: it holds the writer lease from the replacement's
    // build through the swap, so no wrap change can land on it between them;
    // a stale carry would fail the archive's first open.
    let Some(mirror_name) = archive_mirror.file_name().and_then(|name| name.to_str()) else {
        return left_whole();
    };
    // The mirror lands before the rename, as the restore's own archive does.
    if let Err(error) = write_private_file(parent, mirror_name, &mirror_bytes) {
        tracing::warn!(
            %error,
            staging = %staging.display(),
            archive = %archive.display(),
            "the archive mirror was not written; the staged vault is left whole where it is"
        );
        return left_whole();
    }
    #[cfg(unix)]
    let renamed = rustix::fs::renameat_with(
        rustix::fs::CWD,
        &staged_vault,
        rustix::fs::CWD,
        &archive,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(std::io::Error::from);
    #[cfg(not(unix))]
    let renamed = std::fs::rename(&staged_vault, &archive);
    if let Err(error) = renamed {
        // The rename lost, so the mirror just written goes: the inline body
        // of `discard_archive_mirror`, which needs a live swap to call.
        if let Ok(written) = page_seal_custody_path(&archive) {
            let _ = std::fs::remove_file(written);
        }
        tracing::warn!(
            %error,
            staging = %staging.display(),
            archive = %archive.display(),
            "the staged vault was not claimed; it is left whole where it is"
        );
        return left_whole();
    }
    // The claim landed; a sync that fails is reported but keeps it.
    if let Err(error) = sync_dir(parent) {
        tracing::warn!(
            %error,
            archive = %archive.display(),
            "a staged vault was claimed but the directory sync failed"
        );
    }
    if let Err(error) = oneiron::world_keys::finish_restore_archive_mirror(&archive, &previous_seal)
    {
        tracing::warn!(
            %error,
            archive = %archive.display(),
            "a staged vault was claimed but its page-seal mirror could not be finished"
        );
    }
    // Only the staging mirror and the staging directory itself go, never a
    // tree: anything left is residue, reported, never fatal.
    let mut residue = false;
    if let Err(error) = std::fs::remove_file(&staged_mirror) {
        tracing::warn!(
            %error,
            staging = %staged_mirror.display(),
            "a claimed restore's staging mirror is left where it is"
        );
        residue = true;
    }
    if let Err(error) = std::fs::remove_dir(staging) {
        tracing::warn!(
            %error,
            staging = %staging.display(),
            "a claimed restore's staging directory is left where it is"
        );
        residue = true;
    } else {
        // The staging is gone, so the lock file may go too.
        claim_guard.release();
    }
    if let Err(error) = sync_dir(parent) {
        tracing::warn!(
            %error,
            archive = %archive.display(),
            "a staged vault was claimed but the directory sync failed"
        );
        residue = true;
    }
    if residue {
        let note = format!(
            "an earlier interrupted restore left a whole vault in its staging \
             directory {}; it was the previous vault and is now claimed as {}; \
             its staging residue is left where it is",
            staging.display(),
            archive.display()
        );
        tracing::warn!(
            staging = %staging.display(),
            archive = %archive.display(),
            "{note}"
        );
        note
    } else {
        let note = format!(
            "an earlier interrupted restore left a whole vault in its staging \
             directory {}; it was the previous vault and is now claimed as {}",
            staging.display(),
            archive.display()
        );
        tracing::warn!(
            staging = %staging.display(),
            archive = %archive.display(),
            "{note}"
        );
        note
    }
}

/// What a restore where no vault was made.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct RestoredFresh {
    pub(crate) backup: PathBuf,
    pub(crate) checkpoint_id: String,
    pub(crate) vault: PathBuf,
    pub(crate) kinds: BTreeMap<String, u64>,
    pub(crate) entities: u64,
    /// Claim-bound gate decisions not brought back, by id (hex): the backup
    /// predates custody heads and their keys stayed on the old host.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) dropped_gate_decisions: Vec<String>,
    /// Why they were dropped, when any were.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) dropped_reason: Option<&'static str>,
    /// What the restore says about the custody head it used: "rollback not
    /// proven: no custody anchor configured" with no anchor root set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) custody_note: Option<String>,
    /// What the restore costs the vault's publisher training: set when it
    /// brought no training link key (FIX 5892).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) training_note: Option<String>,
    /// The home tables the restore took from the image because the live
    /// vault's rows did not read (FIX 5661 C2b).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) home_table_notes: Vec<String>,
    /// The world key pads the restore did not land at rest (KS-5): erased
    /// since the backup, withheld by their world's sealed copies setting, or
    /// pending as in the vault it replaced.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) pad_notes: Vec<String>,
    /// The credential values the restore did not land readable (KS-6), by
    /// handle and generation, each with its remedy.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) credential_notes: Vec<String>,
    /// What the restore did not carry of its source's current pad objects
    /// (PAD-1), each as the engine words it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) pad_object_notes: Vec<String>,
}

/// Why a new-host restore of a backup that names no custody head left a
/// claim-bound gate decision out (CALLS CUSTODY_NO_HEAD_GATE_ROWS).
const KEY_STAYED_ON_OLD_HOST: &str = "its claim key stayed on the host the backup was taken on:      the backup predates custody heads";

/// Restores `backup` into a new vault at `vault_path`, where none is: the
/// restore on a clean host. The vault takes the backup's vault's place. Its
/// exterior key custody is this host's when it is here; otherwise the
/// custody head `custody` finds beside the backup is admitted and lands
/// with the vault (refused when a configured anchor is missing or stale, or
/// the head's seal, chain or coverage is bad), and a backup that names no
/// head comes back without the claim-bound gate rows whose keys stayed on
/// the old host, each listed. The vault comes back open, its writer lease
/// held, for the caller to unlock its data key and wrap it to this install.
///
/// `finish` runs on the restored vault before it is kept, so the caller wraps
/// its key to this install before the vault is published; a refusal there
/// removes the vault, its page-seal mirror and any custody it landed.
pub(crate) fn restore_fresh(
    backup: &Path,
    vault_path: &Path,
    config: oneiron::VaultConfig,
    key: &CheckpointKey,
    custody: &CustodyRecovery<'_>,
    finish: impl FnOnce(&oneiron::Vault) -> oneiron::Result<()>,
) -> anyhow::Result<(oneiron::Vault, RestoredFresh)> {
    // An owner's key carries no host-order family: the engine's `finish`
    // argument for one is always none here (FIX 6817).
    let finish = |vault: &oneiron::Vault, _: Option<&HostOrderHolds>| finish(vault);
    let path = std::path::absolute(vault_path)?;
    anyhow::ensure!(
        !path.join("data.mdb").exists(),
        "vault {} exists; a restore over it keeps its authority and custody",
        path.display()
    );
    let (restored, report) = oneiron::Vault::restore_checkpoint_recovering(
        backup,
        key,
        &path,
        config,
        now_unix_ms() / 1_000,
        custody,
        finish,
    )
    .map_err(|error| anyhow::anyhow!("backup {} does not restore: {error}", backup.display()))?;
    let kinds = kind_counts(&restored)?;
    Ok((
        restored,
        RestoredFresh {
            backup: backup.to_path_buf(),
            checkpoint_id: report.epoch.checkpoint_id,
            vault: path,
            entities: kinds.values().sum(),
            kinds,
            dropped_reason: (!report.dropped_gate_decisions.is_empty())
                .then_some(KEY_STAYED_ON_OLD_HOST),
            dropped_gate_decisions: report.dropped_gate_decisions,
            custody_note: report.custody_note,
            training_note: report.training_note,
            home_table_notes: report
                .home_table_notes
                .iter()
                .map(ToString::to_string)
                .collect(),
            pad_notes: report.pad_notes.iter().map(ToString::to_string).collect(),
            credential_notes: report
                .credential_notes
                .iter()
                .map(ToString::to_string)
                .collect(),
            pad_object_notes: report
                .pad_object_notes
                .iter()
                .map(ToString::to_string)
                .collect(),
        },
    ))
}

/// What `oneiron restore --activate` did.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Activated {
    /// The previous vault, now a side vault with key custody of its own.
    pub(crate) vault: PathBuf,
    /// The vault that replaced it, whose custody it forked.
    pub(crate) replaced_by: PathBuf,
    /// Set when another user could change a directory on that vault's path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) shared_path: Option<SharedPathWarning>,
    /// Claim-bound decisions dropped because their keys stayed on another
    /// host, by id, as a restore names them (FIX 6033).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) dropped_gate_decisions: Vec<String>,
    /// What the activation says about the custody it forked: rollback is
    /// not proven when no anchor is configured (FIX 6033).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) custody_note: Option<String>,
    /// What the activation costs the vault's publisher training: set when
    /// its training link key did not come with it (FIX 5892, FIX 6033).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) training_note: Option<String>,
    /// The home tables the activation took from the image because the live
    /// vault's rows did not read (FIX 5661 C2b).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) home_table_notes: Vec<String>,
    /// The world key pads the activation took out because the vault that
    /// replaced it erased them since (KS-5).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) pad_notes: Vec<String>,
    /// The credential values the activation did not land readable (KS-6),
    /// by handle and generation, each with its remedy.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) credential_notes: Vec<String>,
    /// What the activation did not carry of its source's current pad
    /// objects (PAD-1), each as the engine words it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) pad_object_notes: Vec<String>,
}

/// Activates the archived vault a restore over `vault_path` set aside at
/// `previous`, as a side vault of the vault that replaced it. Its key custody
/// forks as a rehearsal's does: from then on an erase in either vault never
/// reaches the other's keys. `vault_path` is read off the disk, so a `serve`
/// may hold it; a sealed one reads with `live_seal`. The archive keeps its
/// own tier: `config` carries the seal its own mirror unlocked, if any.
pub(crate) fn activate(
    previous: &Path,
    vault_path: &Path,
    config: oneiron::VaultConfig,
    live_seal: Option<VaultPageSeal>,
) -> anyhow::Result<Activated> {
    let source = SideRestoreSource::read(vault_path, live_seal)
        .map_err(|error| anyhow::anyhow!("read vault {}: {error}", vault_path.display()))?;
    let report = oneiron::Vault::activate_archived(previous, config, &source)
        .map_err(|error| anyhow::anyhow!("activate {}: {error}", previous.display()))?;
    Ok(Activated {
        vault: previous.to_path_buf(),
        replaced_by: vault_path.to_path_buf(),
        shared_path: shared_path_warning(&source),
        dropped_gate_decisions: report.dropped_gate_decisions,
        custody_note: report.custody_note,
        training_note: report.training_note,
        home_table_notes: report
            .home_table_notes
            .iter()
            .map(ToString::to_string)
            .collect(),
        pad_notes: report.pad_notes.iter().map(ToString::to_string).collect(),
        credential_notes: report
            .credential_notes
            .iter()
            .map(ToString::to_string)
            .collect(),
        pad_object_notes: report
            .pad_object_notes
            .iter()
            .map(ToString::to_string)
            .collect(),
    })
}

/// Where a restored vault's tier comes from ([`restore_target_seal`]).
pub(crate) enum RestoreTarget<'a> {
    /// Over or beside a vault, sealed under this seal or plain.
    Beside(Option<&'a VaultPageSeal>),
    /// Where no vault is: sealed when the config's `maximum_tier` asks, under
    /// the data key `key` unlocked from the backup.
    Fresh {
        maximum_tier: bool,
        key: &'a CheckpointKey,
    },
}

/// The page seal a restored vault is created under (OF-570 maximum tier),
/// one rule for every restore. Over a vault or beside it (a rehearsal), the
/// copy keeps that vault's tier, under a fresh incarnation of its seal. Where
/// no vault is, it follows the config's `maximum_tier`, under the backup's
/// own vault id and data key. An activated archive is no restore: it keeps
/// its own tier and opens with its own mirror. `None` is a plain vault.
pub(crate) fn restore_target_seal(
    target: RestoreTarget<'_>,
) -> anyhow::Result<Option<VaultPageSeal>> {
    match target {
        RestoreTarget::Beside(seal) => {
            Ok(seal.map(VaultPageSeal::fresh_incarnation).transpose()?)
        }
        RestoreTarget::Fresh {
            maximum_tier: false,
            ..
        } => Ok(None),
        RestoreTarget::Fresh { key, .. } => key.restored_page_seal()?.map(Some).ok_or_else(|| {
            anyhow::anyhow!(
                "the maximum tier restores a backup under its own data key, and this key did not \
                 come from the backup"
            )
        }),
    }
}

/// Atomically exchanges two directory entries.
pub(super) fn exchange(a: &Path, b: &Path) -> std::io::Result<()> {
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
