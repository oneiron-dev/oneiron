//! The relay locker's delete guard (FIX 1488, Engine 10-20 20:3x). The host
//! injects one through [`super::run_relay_with_hold_guard`], and the locker
//! delete runs through it (`super::deferred_delete`).
//!
//! A locker delete hands the guard its target and its unlink. Under a
//! standing backup-keeping legal hold of the vault the delete defers, with
//! only whether the owner may see a hold that stands (FIX 9500); when the
//! holds cannot be read, because the vault does not open or the read fails,
//! it defers too (`hold_state_unknown`), never deletes. The retirement of a
//! generation a guarded upload kept (FIX 1283) runs through the same guard,
//! its target naming that generation. An in-process guard runs the unlink, then its directory
//! sync, inside the hold read's exclusion, so a hold placed meanwhile
//! commits before the read or after the sync. A guard over a vault engine
//! that runs as another process delegates the delete instead (FIX 6826,
//! `super::ctl_hold_guard`): the engine claims, unlinks and syncs the object
//! inside that same exclusion, and the unlink the guard is handed never
//! runs. A deferred delete asks again when [`RelayDeleteHoldGuard::subscribe_rechecks`]
//! moves: after a committed hold release, after each hold maintenance pass,
//! and when the guard's vault first resolves or is rebound. A relay with no
//! guard deletes as it does today.

use oneiron_vault_contract::relay_delete::{RelayDeleteGeneration, RelayHoldVisibility};

/// What the name of a generation an upload kept starts with, before its
/// object and its generation id: `.preimage-<object>-<generation>`. A dot
/// name, so a listing and a read never show it.
pub(crate) const PREIMAGE_PREFIX: &str = ".preimage-";

/// One locker object generation a relay delete would unlink.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelayDeleteTarget {
    /// The vault the locker room belongs to.
    pub(crate) vault_id: [u8; 32],
    /// The locker object: 64 lowercase hex, or `manifest`.
    pub(crate) object_id: String,
    /// The object's current file, or a generation an upload kept.
    pub(crate) generation: RelayDeleteGeneration,
    /// The BLAKE3 digest of the stored ciphertext the delete names.
    pub(crate) ciphertext_blake3: [u8; 32],
}

impl RelayDeleteTarget {
    /// The name of the file the target names in the objects directory: the
    /// object for the current one, `.preimage-<object>-<generation>` for one
    /// an upload kept. Built from validated fields, never a caller's path.
    pub(crate) fn leaf(&self) -> String {
        match &self.generation {
            RelayDeleteGeneration::Current => self.object_id.clone(),
            RelayDeleteGeneration::Preimage { generation_id } => {
                format!("{PREIMAGE_PREFIX}{}-{generation_id}", self.object_id)
            }
        }
    }
}

/// Why a delete waits instead of unlinking. Nothing is refused: the
/// delete's intent stays and runs again on a recheck.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelayDeleteDeferral {
    /// A standing legal hold keeps every backup copy of the vault;
    /// `visibility` says only whether the owner may see a hold that stands.
    Held { visibility: RelayHoldVisibility },
    /// The holds could not be read: the vault did not open, or the read
    /// failed.
    HoldStateUnknown,
}

/// What became of one guarded delete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelayDeleteHoldOutcome {
    /// No hold stood, and the object is gone: unlinked, or found gone by
    /// the engine that executes the delete, and its directory synced.
    Deleted,
    /// The object stays.
    Deferred(RelayDeleteDeferral),
}

/// A guarded delete that did not finish.
#[derive(Debug)]
pub(crate) enum RelayDeleteHoldError {
    /// The unlink or its directory sync failed: nothing is claimed deleted.
    StorageIo(std::io::Error),
    /// The guard itself cannot run.
    GuardUnavailable,
}

/// The hold check a relay locker delete runs through.
pub(crate) trait RelayDeleteHoldGuard: Send + Sync {
    /// Deletes `target` only while no standing hold keeps the vault's
    /// backups, inside the hold read's exclusion: through `unlink` (the
    /// unlink, then its directory sync), or, for a guard that delegates the
    /// delete to the vault's engine, through the engine's own claim, unlink
    /// and sync, `unlink` never run. Never [`RelayDeleteHoldOutcome::Deleted`]
    /// when the holds could not be read or the delete is not confirmed.
    ///
    /// # Errors
    ///
    /// The unlink failed, or the guard cannot run.
    fn delete_if_released(
        &self,
        target: &RelayDeleteTarget,
        unlink: &mut dyn FnMut() -> std::io::Result<()>,
    ) -> Result<RelayDeleteHoldOutcome, RelayDeleteHoldError>;

    /// A content-free counter that moves after a committed hold release,
    /// after each hold maintenance pass, and when the guard's vault first
    /// resolves or is rebound: a deferred delete asks again then.
    fn subscribe_rechecks(&self) -> tokio::sync::watch::Receiver<u64>;
}
