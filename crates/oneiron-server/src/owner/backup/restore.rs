//! Restores of one vault's backups: over the stopped vault, where no vault
//! is yet, and the activation of the vault a restore set aside (moved out of
//! `backup` whole).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use oneiron::VaultPageSeal;
use oneiron::recovery::checkpoint::{CheckpointKey, CustodyRecovery, SideRestoreSource};
use oneiron::world_keys::VaultKeyUnlock;
use serde::Serialize;

use super::super::stamp::{file_stamp, now_unix_ms};
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
/// The backup opens with `keystore`, the install's configured one, or the
/// platform's at its defaults when there is none.
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
    restore_over_with(backup, vault_path, config, |_| Ok(key), exchange, sync_dir)
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
    // carries, and trusts the signers it holds.
    let open_key = |vault_path: &Path| match keystore {
        Some(keystore) => CheckpointKey::unlock(backup, &VaultKeyUnlock::Device(keystore.as_ref()))
            .map(|key| key.trusting_device(keystore)),
        None => CheckpointKey::unlock_on_this_device(backup, vault_path),
    };
    restore_over_with(
        backup,
        vault_path,
        config,
        |vault_path| open_key(vault_path).map_err(anyhow::Error::from),
        swap,
        sync_after_swap,
    )
}

fn restore_over_with(
    backup: &Path,
    vault_path: &Path,
    config: oneiron::VaultConfig,
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
    // The backup opens before anything is made.
    let key = open_key(vault_path.as_path())
        .map_err(|error| anyhow::anyhow!("backup {} does not open: {error:#}", backup.display()))?;
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
    let staging = Owned::create(vault_path.with_file_name(format!(".{name}.restore-{stamp}")))?;
    let live = match oneiron::Vault::open_owned(vault_path, config) {
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
    // A sealed vault's mirror sits beside its directory and stays put in the
    // exchange: until the swap is confirmed, the mirrors beside both name
    // both incarnations, so each environment opens wherever it ends up.
    let sealed_swap = match live.stage_sealed_swap(&restored) {
        Ok(sealed_swap) => sealed_swap,
        Err(error) => {
            drop(restored);
            staging.remove();
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
    })
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
    oneiron::Vault::activate_archived(previous, config, &source)
        .map_err(|error| anyhow::anyhow!("activate {}: {error}", previous.display()))?;
    Ok(Activated {
        vault: previous.to_path_buf(),
        replaced_by: vault_path.to_path_buf(),
        shared_path: shared_path_warning(&source),
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
