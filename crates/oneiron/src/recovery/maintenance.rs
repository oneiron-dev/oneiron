//! The canonical snapshot as one owner maintenance act (ARCH-0038 escape
//! hatch and recovery ladder): capture a window, recover it from the
//! artifact held in memory, and write no snapshot file. The re-bootstrap act
//! then installs the rebuilt state as the window's CRDT state (OF-005).

use std::fs;
use std::path::{Path, PathBuf};

use super::canonical::{capture_canonical_window_within, invalid};
use super::{CanonicalSnapshot, RecoveryBudget, RecoveryTier, recover_vault_window};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, GateError, Result};
use crate::store::legal_hold::HoldActor;
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

/// What one canonical window re-bootstrap did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowRebootstrapReport {
    /// The recovery the re-bootstrap ran first.
    pub recovery: WindowRecoveryReport,
    /// Root-map keys of the window's document that took their rebuilt value
    /// or went because the rebuilt state lacks them.
    pub rewritten_keys: usize,
    /// The installed window's version vector, encoded. Its root is the
    /// window's newest operation: a peer whose vector does not cover it
    /// resyncs from a replacement.
    pub version: Vec<u8>,
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
        self.canonical_window_act(owner, window, dir, budget, false)
            .map(|(recovery, _)| recovery)
    }

    /// Recovers `window` as [`Self::recover_window_from_canonical_snapshot`]
    /// does, then re-bootstraps it (ARCH-0038, a pathological window): the
    /// rebuilt state becomes the window's durable CRDT state, with no history
    /// behind it, as one owner act. The window's document takes the rebuilt
    /// value of each key it differs on and is cut to a shallow snapshot at its
    /// newest operation, so it stays the same lineage and every peer resyncs
    /// through the history-free door: a peer behind the cut takes a
    /// replacement and writes its unseen writes back on top
    /// ([`crate::sync::window::prepare_replacement`]).
    ///
    /// The cut drops every row's history, as an erase does: a legal hold on
    /// any row the window carries refuses it before the recovery runs, and
    /// again in the install transaction. The installed window must capture
    /// to the very canonical artifact the act recovered from, or nothing is
    /// installed.
    pub fn rebootstrap_window_from_canonical_snapshot(
        &self,
        owner: &AuthenticatedOwner,
        window: &str,
        dir: &Path,
        budget: RecoveryBudget,
    ) -> Result<WindowRebootstrapReport> {
        let (recovery, installed) = self.canonical_window_act(owner, window, dir, budget, true)?;
        let (rewritten_keys, version) =
            installed.ok_or_else(|| invalid("re-bootstrap installed nothing"))?;
        Ok(WindowRebootstrapReport {
            recovery,
            rewritten_keys,
            version,
        })
    }

    /// The one canonical window act: recovery, and with `rebootstrap` the
    /// install of the rebuilt state, returning the keys it rewrote and the
    /// installed version.
    fn canonical_window_act(
        &self,
        owner: &AuthenticatedOwner,
        window: &str,
        dir: &Path,
        budget: RecoveryBudget,
        rebootstrap: bool,
    ) -> Result<(WindowRecoveryReport, Option<(usize, Vec<u8>)>)> {
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
        let actor = {
            let txn = self.store.env.read_txn()?;
            let actor = owner.revalidate_in_txn(self, &txn)?;
            // An authenticated human is not by that alone this vault's owner.
            if !crate::policy_model::is_live_vault_owner_in_txn(self, &txn, &actor)? {
                return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                    "window recovery is an owner act, and the actor is no owner of this vault",
                )));
            }
            HoldActor::owner(actor)
        };
        let doc = durable_window_doc(self, &key)?;
        if rebootstrap {
            crate::sync::window::reject_held_rebootstrap(self, &doc, &actor)?;
        }
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
        let installed = if rebootstrap {
            // The recovery left the rebuilt document equivalent to the
            // artifact; the window's own cut of it must be too.
            let cut = crate::sync::window::prepare_rebootstrap(self, &key, &prepared.window)?;
            if capture_canonical_window_within(self, window, &cut.doc, budget.max_bytes)?
                != snapshot
            {
                return Err(invalid("re-bootstrapped window is not equivalent"));
            }
            let rewritten = cut.rewritten;
            let installed = cut.install(self, &actor)?;
            Some((
                rewritten,
                crate::sync::loro_support::doc_version_vector(&installed),
            ))
        } else {
            None
        };
        Ok((
            WindowRecoveryReport {
                window: window.to_owned(),
                tier: prepared.tier,
                manifest_path,
                quarantine_path: prepared.quarantine_path,
                obligations: prepared.obligations,
                snapshot_blake3,
            },
            installed,
        ))
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
