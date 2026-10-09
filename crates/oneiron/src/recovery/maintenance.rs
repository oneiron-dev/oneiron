//! The canonical snapshot as one owner maintenance act (ARCH-0038 escape
//! hatch and recovery ladder): capture a window, recover it from the
//! artifact, and keep no snapshot file.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use super::canonical::invalid;
use super::{
    CanonicalSnapshot, RecoveryBudget, RecoveryTier, recover_vault_window,
    write_canonical_window_snapshot,
};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::sync::types::WindowKey;
use crate::{Vault, VaultWriterLease};

/// What one canonical window recovery did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowRecoveryReport {
    pub window: String,
    pub tier: RecoveryTier,
    /// The window's recovery manifest: chunk hashes, no content. It stays.
    pub manifest_path: PathBuf,
    /// A bad manifest the ladder renamed intact beside the manifest.
    pub quarantine_path: Option<PathBuf>,
    /// The chunks the recovery rebuilt.
    pub obligations: Vec<String>,
    /// blake3 of the canonical artifact the act wrote, read back and deleted.
    pub snapshot_blake3: [u8; 32],
}

impl Vault {
    /// Recovers `window` from a canonical snapshot of its durable CRDT state,
    /// as one owner maintenance act. The window's writers must be stopped:
    /// this process holds the vault's writer lease and no sync window manager
    /// is live, so nothing writes the window between capture and recovery.
    ///
    /// The snapshot is written through the artifact door, read back, and
    /// deleted before the recovery runs, whatever the outcome. A kept snapshot
    /// is a restorable image, and none is kept until the exterior erasure
    /// ledger and key custody land (ARCH-0038 `#erasure-completeness`). `dir`
    /// keeps only the window's manifest and any manifest the ladder
    /// quarantined beside it.
    pub fn recover_window_from_canonical_snapshot(
        &self,
        owner: &AuthenticatedOwner,
        window: &str,
        dir: &Path,
        budget: RecoveryBudget,
    ) -> Result<WindowRecoveryReport> {
        let key = WindowKey::try_new(window).ok_or_else(|| invalid("window key"))?;
        if !self
            .writer_lease()
            .is_some_and(VaultWriterLease::held_by_current_process)
        {
            return Err(Error::ConcurrentWrite(
                "window recovery needs this process to hold the vault's writer lease",
            ));
        }
        if self
            .live_window_manager
            .lock()
            .map_err(|_| Error::ConcurrentWrite("live window manager lock poisoned"))?
            .upgrade()
            .is_some()
        {
            return Err(Error::ConcurrentWrite(
                "window recovery needs the window's writers stopped",
            ));
        }
        {
            let txn = self.store.env.read_txn()?;
            owner.revalidate_in_txn(self, &txn)?;
        }
        let doc = durable_window_doc(self, &key)?;
        create_private_dir(dir)?;
        let snapshot_path = dir.join(format!("{window}.canonical"));
        let manifest_path = dir.join(format!("{window}.manifest"));
        // An interrupted act may have left its artifact behind.
        remove_snapshot_files(dir, window)?;
        let read = (|| {
            let digest = write_canonical_window_snapshot(self, window, &doc, &snapshot_path)?;
            let mut bytes = Vec::new();
            fs::File::open(&snapshot_path)?
                .take(budget.max_bytes.saturating_add(1) as u64)
                .read_to_end(&mut bytes)?;
            if *blake3::hash(&bytes).as_bytes() != digest {
                return Err(invalid("canonical snapshot changed on disk"));
            }
            Ok((digest, CanonicalSnapshot::decode(&bytes)?))
        })();
        remove_snapshot_files(dir, window)?;
        let (snapshot_blake3, snapshot) = read?;
        let prepared = recover_vault_window(
            self,
            &crate::sync::bridge::Materializer::new(),
            &manifest_path,
            &snapshot,
            budget,
        )?;
        Ok(WindowRecoveryReport {
            window: window.to_owned(),
            tier: prepared.tier,
            manifest_path,
            quarantine_path: prepared.quarantine_path,
            obligations: prepared.obligations,
            snapshot_blake3,
        })
    }
}

/// The window as its durable CRDT state holds it: the persisted snapshot and
/// every pending update, the first steps of a window open. Nothing is read
/// back from LMDB, which is what a recovery may be repairing.
fn durable_window_doc(vault: &Vault, key: &WindowKey) -> Result<loro::LoroDoc> {
    match crate::sync::window::load_window_from_state(vault, "", key) {
        Ok(doc) => Ok(doc),
        Err(Error::Sync(crate::error::SyncError::WindowNotFound { .. })) => {
            let doc = crate::sync::schema::create_window_doc("", key);
            if crate::sync::window::apply_pending_window_updates(vault, &doc, key)? == 0 {
                return Err(invalid("window has no durable CRDT state"));
            }
            Ok(doc)
        }
        Err(error) => Err(error),
    }
}

fn create_private_dir(dir: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)?;
    Ok(())
}

/// Deletes the window's canonical artifact and any temporary file its writer
/// left, then syncs the directory so the unlink is durable.
fn remove_snapshot_files(dir: &Path, window: &str) -> Result<()> {
    let published = format!("{window}.canonical");
    let temporary = format!("{window}.snapshot-");
    let mut removed = false;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name == published || name.starts_with(&temporary) {
            fs::remove_file(entry.path())?;
            removed = true;
        }
    }
    if removed {
        super::quarantine::sync_parent(&dir.join(published))?;
    }
    Ok(())
}
