//! A shadow arm's bodies at its host (PR-S1), kept for the caller under an
//! opaque lease: one directory per arm, under one directory per runner,
//! under the host's temporary directory (CALLS "arm lease lifetime"). A read
//! needs the arm's lease; releasing the lease frees the arm, and its
//! directory goes once its last in-flight reader is done. A failed or
//! cancelled arm keeps its lease too, for its partial evidence. A runner's
//! directory is held by a lock while the runner lives, and a runner that
//! opens removes every runner directory no live runner holds, so a host
//! that stopped leaves nothing behind past its next start. No arm has a
//! vault of its own in PR-S1: its bodies are plain files, never the vault's.

use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use oneiron::code_run::shadow_runner::{ShadowArmLease, ShadowBodyStore};
use oneiron::{EntityId, Result};

/// The directory under the host's temporary directory that runners keep
/// their arms in.
const ARMS_SCRATCH: &str = "oneiron-shadow-arms";

/// The lock file a runner's directory is held by while its runner lives.
const HELD_LOCK: &str = ".held";

/// The arms a runner keeps, by lease.
type Arms = HashMap<ShadowArmLease, Arc<ArmEntry>>;

/// One arm's bodies, while its lease or a reader holds them.
pub(super) struct ArmEntry {
    store: ShadowBodyStore,
}

impl ArmEntry {
    /// The arm's store.
    pub(super) const fn store(&self) -> &ShadowBodyStore {
        &self.store
    }
}

impl Drop for ArmEntry {
    fn drop(&mut self) {
        // The arm's bodies go with its last holder.
        if let Err(error) = std::fs::remove_dir_all(self.store.root()) {
            tracing::debug!(kind = ?error.kind(), "a shadow arm's bodies were not removed");
        }
    }
}

/// One runner's arms.
pub(super) struct ArmRegistry {
    root: PathBuf,
    /// Held while the registry lives: a later runner's sweep takes it only
    /// once this one is gone.
    _held: File,
    arms: Mutex<Arms>,
}

impl ArmRegistry {
    /// A runner's arms, in a directory of its own under the host's
    /// temporary directory, once every runner directory there that no live
    /// runner holds is removed.
    pub(super) fn open() -> Result<Self> {
        let scratch = std::env::temp_dir().join(ARMS_SCRATCH);
        make_private_dir(&scratch)?;
        sweep(&scratch);
        let root = scratch.join(EntityId::now().to_hex());
        make_private_dir(&root)?;
        let held = File::create(root.join(HELD_LOCK))?;
        held.lock()?;
        Ok(Self {
            root,
            _held: held,
            arms: Mutex::default(),
        })
    }

    /// A new arm under `lease`, its store made.
    pub(super) fn open_arm(&self, lease: ShadowArmLease) -> Result<Arc<ArmEntry>> {
        let store = ShadowBodyStore::open(self.root.join(lease.to_hex()))?;
        let entry = Arc::new(ArmEntry { store });
        self.arms().insert(lease, Arc::clone(&entry));
        Ok(entry)
    }

    /// The arm `lease` holds, while it does.
    pub(super) fn get(&self, lease: &ShadowArmLease) -> Option<Arc<ArmEntry>> {
        self.arms().get(lease).cloned()
    }

    /// Releases `lease`: its arm's bodies go once no reader holds them.
    /// Whether it held an arm.
    pub(super) fn release(&self, lease: &ShadowArmLease) -> bool {
        let released = self.arms().remove(lease);
        released.is_some()
    }

    fn arms(&self) -> MutexGuard<'_, Arms> {
        self.arms.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Drop for ArmRegistry {
    fn drop(&mut self) {
        // The runner's arms go with it; a reader still holding one reads
        // nothing more.
        if let Err(error) = std::fs::remove_dir_all(&self.root) {
            tracing::debug!(kind = ?error.kind(), "a shadow runner's arms were not removed");
        }
    }
}

/// `path`, made 0700 with its parents when absent.
fn make_private_dir(path: &Path) -> Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(path)?;
    Ok(())
}

/// Removes every runner directory under `scratch` whose lock no live runner
/// holds. Best effort: one it cannot open, lock or remove stays, and a
/// removal that fails is logged.
fn sweep(scratch: &Path) {
    let Ok(entries) = std::fs::read_dir(scratch) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(held) = File::open(path.join(HELD_LOCK)) else {
            continue;
        };
        if held.try_lock().is_ok()
            && let Err(error) = std::fs::remove_dir_all(path)
        {
            tracing::debug!(kind = ?error.kind(), "a stopped shadow runner's arms were not removed");
        }
    }
}
