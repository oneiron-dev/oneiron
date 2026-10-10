//! The canonical snapshot as one owner maintenance act (ARCH-0038 escape
//! hatch and recovery ladder): capture a window, recover it from the
//! artifact held in memory, and write no snapshot file.

use std::fs;
use std::path::{Path, PathBuf};

use super::canonical::{capture_canonical_window_within, invalid};
use super::{CanonicalSnapshot, RecoveryBudget, RecoveryTier, recover_vault_window};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, GateError, Result};
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
    /// blake3 of the canonical artifact the act captured and recovered from.
    pub snapshot_blake3: [u8; 32],
}

impl Vault {
    /// Recovers `window` from a canonical snapshot of its durable CRDT state,
    /// as one owner maintenance act. The window's writers must be stopped:
    /// this process holds the vault's writer lease and no sync window manager
    /// is live, so nothing writes the window between capture and recovery.
    ///
    /// The snapshot never touches disk. A snapshot file is a restorable
    /// plaintext image that a crash between writing and unlinking it would
    /// keep, and none may exist until the exterior erasure ledger and key
    /// custody land (ARCH-0038 `#erasure-completeness`). The artifact is
    /// encoded and decoded in memory instead, and a window whose artifact
    /// exceeds `budget.max_bytes` is refused with
    /// [`ArtifactError::OverlayLimit`](crate::error::ArtifactError::OverlayLimit)
    /// rather than spilled. The budget bounds what the act copies, not only
    /// what it keeps: the capture stops copying at `budget.max_bytes` (past
    /// it by one document at most, read whole as opening it reads it), and
    /// the encoding stops writing there. `dir` holds only the window's
    /// manifest and any manifest the ladder quarantined beside it.
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
            // An authenticated human is not by that alone this vault's owner.
            if !crate::policy_model::is_live_vault_owner_in_txn(self, &txn, &owner.actor())? {
                return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                    "window recovery is an owner act, and the actor is no owner of this vault",
                )));
            }
        }
        let doc = durable_window_doc(self, &key)?;
        // The artifact envelope round trip, in memory: what recovers is what
        // a written snapshot would have held, byte for byte.
        let bytes = capture_canonical_window_within(self, window, &doc, budget.max_bytes)?
            .encode_within(budget.max_bytes)?;
        let snapshot_blake3 = *blake3::hash(&bytes).as_bytes();
        let snapshot = CanonicalSnapshot::decode(&bytes)?;
        drop(bytes);
        create_private_dir(dir)?;
        let manifest_path = dir.join(format!("{window}.manifest"));
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
