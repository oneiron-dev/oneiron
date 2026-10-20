//! Rehearsals of one vault's backups: restored into a scratch copy beside
//! the live vault, opened, checked and reported (moved out of `backup`
//! whole).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use oneiron::recovery::checkpoint::{CheckpointKey, SideRestoreSource};
use serde::Serialize;

use super::super::stamp::now_unix_ms;
use super::{RestoreTarget, kind_counts, restore_target_seal, write_budget};
use crate::machine::DiskFloor;

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
    /// Set when another user could change a directory on the live vault's
    /// path, read off the disk for this rehearsal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) shared_path: Option<SharedPathWarning>,
    /// What a restore of this backup costs the vault's publisher training:
    /// set when it brought no training link key (FIX 5892).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) training_note: Option<String>,
}

/// A directory on the live vault's path that another user could change,
/// found when a rehearsal or an activation read the vault off the disk. It
/// still ran: the vault opens and writes there as it is.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct SharedPathWarning {
    pub(crate) directory: PathBuf,
    /// What another user could do there, and the `chmod` that stops it.
    pub(crate) fix: String,
}

#[cfg(unix)]
pub(super) fn shared_path_warning(source: &SideRestoreSource) -> Option<SharedPathWarning> {
    source.shared_path().map(|shared| SharedPathWarning {
        directory: shared.directory.clone(),
        fix: shared.to_string(),
    })
}

#[cfg(not(unix))]
pub(super) fn shared_path_warning(_: &SideRestoreSource) -> Option<SharedPathWarning> {
    None
}

/// Restores `backup` into a scratch directory, opens it, checks it and
/// reports. The live vault is never opened; `source` is its key-custody state,
/// read when the rehearsal starts. The copy is made in a directory this call
/// creates: `keep_at` names it and keeps it, otherwise it is a new directory
/// under the system temp directory and is deleted afterwards.
pub(crate) fn rehearse(
    backup: &Path,
    config: oneiron::VaultConfig,
    keep_at: Option<&Path>,
    source: &SideRestoreSource,
) -> anyhow::Result<Rehearsal> {
    rehearse_in(&std::env::temp_dir(), backup, config, keep_at, source)
}

/// [`rehearse`] with a key the caller unlocked and pinned, in place of the
/// source's.
pub(crate) fn rehearse_keyed(
    backup: &Path,
    config: oneiron::VaultConfig,
    keep_at: Option<&Path>,
    source: &SideRestoreSource,
    key: CheckpointKey,
) -> anyhow::Result<Rehearsal> {
    rehearse_in_with(
        &std::env::temp_dir(),
        backup,
        config,
        keep_at,
        source,
        Some(key),
        &[],
    )
}

/// [`rehearse`], with a scratch directory it does not keep made under `temp`.
pub(crate) fn rehearse_in(
    temp: &Path,
    backup: &Path,
    config: oneiron::VaultConfig,
    keep_at: Option<&Path>,
    source: &SideRestoreSource,
) -> anyhow::Result<Rehearsal> {
    rehearse_in_with(temp, backup, config, keep_at, source, None, &[])
}

/// [`rehearse_in`], the copy's writes claiming their room on each of
/// `floors` a serving host lent ([`write_budget`], FIX 5479, FIX 5612).
pub(super) fn rehearse_in_with(
    temp: &Path,
    backup: &Path,
    config: oneiron::VaultConfig,
    keep_at: Option<&Path>,
    source: &SideRestoreSource,
    key: Option<CheckpointKey>,
    floors: &[DiskFloor],
) -> anyhow::Result<Rehearsal> {
    let scratch = match keep_at {
        Some(path) => path.to_path_buf(),
        None => temp.join(super::scratch::generated_name()),
    };
    // Checked before the scratch directory is made in it.
    #[cfg(unix)]
    oneiron::store::refuse_shared_path(
        std::path::absolute(&scratch)?
            .parent()
            .unwrap_or(Path::new("/")),
    )?;
    let mut scratch = Owned::create(scratch)?;
    // A copy deleted afterwards is marked so, and a start after a stop
    // midway sweeps it; a kept one never is (FIX 5677).
    if keep_at.is_none() {
        scratch.mark_disposable();
    }
    let outcome = rehearse_into(backup, config, &scratch.vault(), source, key, floors);
    // A failed rehearsal leaves nothing behind, even where it was told to keep.
    if keep_at.is_none() || outcome.is_err() {
        scratch.remove();
    }
    let mut rehearsal = outcome?;
    rehearsal.kept = keep_at.is_some();
    rehearsal.shared_path = shared_path_warning(source);
    Ok(rehearsal)
}

fn rehearse_into(
    backup: &Path,
    mut config: oneiron::VaultConfig,
    scratch: &Path,
    source: &SideRestoreSource,
    key: Option<CheckpointKey>,
    floors: &[DiskFloor],
) -> anyhow::Result<Rehearsal> {
    let key = match key {
        Some(key) => key,
        None => source.checkpoint_key(backup).map_err(|error| {
            anyhow::anyhow!("backup {} does not open: {error}", backup.display())
        })?,
    };
    // The copy keeps the live vault's tier: a sealed vault's rows never land
    // in a plain scratch vault.
    config.page_seal = restore_target_seal(RestoreTarget::Beside(source.page_seal()))?;
    // The copy sits beside the live vault, so its key custody forks: an erase
    // in a kept scratch copy never reaches the live vault's keys. Its writes
    // claim their room on the floor, given back once it is made or refused;
    // the engine's error stays the source, so capacity is named (FIX 5479).
    let room = write_budget::WriteClaim::on_each(floors);
    let (restored, report) = oneiron::Vault::restore_checkpoint_beside_within(
        backup,
        &key,
        scratch,
        config,
        source,
        now_unix_ms() / 1_000,
        &room,
    )
    .map_err(|error| {
        anyhow::Error::new(error).context(format!("backup {} does not restore", backup.display()))
    })?;
    drop(room);
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
        shared_path: None,
        training_note: report.training_note,
    })
}

/// A directory this call created, owner-only. A restored copy goes in its
/// `vault` subdirectory, so the copy and any key-custody sibling an open makes
/// beside it stay inside, and removing it removes only what this call made.
pub(super) struct Owned {
    dir: PathBuf,
    /// The directory itself, held open from its creation: removal goes
    /// through it, so a directory moved in under its name is never removed.
    #[cfg(unix)]
    held: std::fs::File,
    /// Its disposable mark, locked until it is removed (`scratch`); `None`
    /// for a kept copy and a restore's staging.
    #[cfg(unix)]
    mark: Option<std::fs::File>,
}

impl Owned {
    pub(super) fn create(dir: PathBuf) -> anyhow::Result<Self> {
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&dir).map_err(|error| {
            anyhow::Error::new(error).context(format!("create {}", dir.display()))
        })?;
        Self::hold(dir)
    }

    /// Opens the directory `create` just made. The open goes through its name
    /// again, so a directory moved in under that name meanwhile is held only
    /// if it could be the one made here: empty, this process's and owner-only.
    /// That is a fitness test, not proof this call made it, but removal then
    /// reaches nothing this call did not put there. Any other directory, or
    /// one that does not open, is refused and left as it is.
    pub(super) fn hold(dir: PathBuf) -> anyhow::Result<Self> {
        #[cfg(unix)]
        let held = {
            use rustix::fs::{Mode, OFlags};
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let held = rustix::fs::open(&dir, flags, Mode::empty())
                .map(std::fs::File::from)
                .map_err(|error| {
                    anyhow::Error::new(std::io::Error::from(error))
                        .context(format!("open {}; it is left as it is", dir.display()))
                })?;
            anyhow::ensure!(
                fresh_private_directory(&held)?,
                "{} is not the directory this call made; it is left as it is",
                dir.display()
            );
            held
        };
        Ok(Self {
            dir,
            #[cfg(unix)]
            held,
            #[cfg(unix)]
            mark: None,
        })
    }

    /// Marks the directory disposable, holding the mark's lock until it is
    /// removed, so a start after this process stops sweeps it (`scratch`,
    /// FIX 5677). A mark that cannot be made is logged and the rehearsal goes
    /// on unmarked: a stop midway then leaves it, as before.
    pub(super) fn mark_disposable(&mut self) {
        #[cfg(unix)]
        match super::scratch::mark(&self.held) {
            Ok(mark) => self.mark = Some(mark),
            Err(error) => tracing::warn!(
                dir = %self.dir.display(),
                %error,
                "rehearsal scratch not marked disposable; a stop midway leaves it"
            ),
        }
        #[cfg(not(unix))]
        let _ = self;
    }

    pub(super) fn vault(&self) -> PathBuf {
        self.dir.join("vault")
    }

    /// Removes the directory with everything in it, only while its name still
    /// holds it; otherwise both are left where they are. Its mark's lock is
    /// given back after.
    pub(super) fn remove(self) {
        #[cfg(unix)]
        let _ = oneiron::store::remove_held_directory(&self.dir, &self.held);
        #[cfg(unix)]
        drop(self.mark);
        #[cfg(not(unix))]
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Whether `held` could be a directory this process just made: its own,
/// owner-only and empty.
#[cfg(unix)]
fn fresh_private_directory(held: &std::fs::File) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let metadata = held.metadata()?;
    if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
        return Ok(false);
    }
    for entry in rustix::fs::Dir::read_from(held)? {
        let entry = entry?;
        if entry.file_name() != c"." && entry.file_name() != c".." {
            return Ok(false);
        }
    }
    Ok(true)
}
