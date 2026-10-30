//! A world kit's settle (FIX 11977, 12046, 12135, 12136): once a confirm
//! commits, the confirmed kit's pending piece moves over this install's
//! current pair, but only while the inventory still reads that kit as
//! current. A settle whose kit a later confirm already replaced leaves the
//! current pair alone and deletes its own pending piece. The settles of one
//! install take turns in this process, so two confirms racing on it never
//! interleave their check and move: each move writes the kit current at its
//! check, and the later kit's own settle runs after it. A settle waits on no
//! network.
//!
//! Each settle then sweeps. The keystore cannot list its slots, so a confirm
//! row names the kits it replaced whose pending piece may still be here
//! ([`StoredKit::stale_pending_pieces`](super::StoredKit::stale_pending_pieces)):
//! a crash before that confirm's own settle leaves them. The sweep deletes
//! each, and a kit leaves its list once the delete succeeds.

use std::collections::BTreeSet;
use std::sync::{Condvar, Mutex, PoisonError};

use super::KITS;
use crate::Vault;
use crate::error::Result;
use crate::recovery::{KitId, KitPiecePair, KitPieceStore, KitSecretKind};
use crate::world_keys::keystore_error;

/// The vault id and machine id that name one install's kit-piece slots.
type VaultInstall = ([u8; 32], [u8; 16]);

/// The installs whose settle runs now in this process.
static SETTLING: Mutex<BTreeSet<VaultInstall>> = Mutex::new(BTreeSet::new());

/// Signalled each time a settle gives back its turn.
static SETTLED: Condvar = Condvar::new();

/// One install's turn to settle: taken once no other settle of that install
/// runs in this process, and given back on drop.
struct SettleTurn(VaultInstall);

impl SettleTurn {
    fn take(install: VaultInstall) -> Self {
        let mut settling = SETTLING.lock().unwrap_or_else(PoisonError::into_inner);
        while settling.contains(&install) {
            settling = SETTLED
                .wait(settling)
                .unwrap_or_else(PoisonError::into_inner);
        }
        settling.insert(install);
        Self(install)
    }
}

impl Drop for SettleTurn {
    fn drop(&mut self) {
        SETTLING
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.0);
        SETTLED.notify_all();
    }
}

impl Vault {
    /// Settles this install's world-kit pieces in its turn (FIX 11977, 12046,
    /// 12135, 12136). With `confirmed`, the kit a confirm just committed:
    /// while the inventory reads it as current, its pending piece, when it
    /// has one, replaces the current pair's, then its pending pair empties;
    /// once a later confirm replaced it, its pending piece is deleted and the
    /// current pair stays. With none, after a confirm that made no kit current
    /// and before a draw keeps its piece, the current kit's pending piece
    /// moves the same way, which retries a move that failed. The sweep then
    /// deletes the pending pieces the confirm rows name, kits that can no
    /// longer be confirmed. The piece of a kit still pending stays, whatever
    /// kit became current. A step that fails is logged and leaves its piece
    /// where it is, where a restore here still reads it, and a swept kit whose
    /// delete failed stays listed for the next settle.
    pub(in crate::world_keys) fn settle_pending_kit_pieces(&self, confirmed: Option<KitId>) {
        let store = match self.kit_piece_store_here() {
            Ok(Some(store)) => store,
            Ok(None) => return,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "this install's kit-piece slots did not open; no world-kit piece moved"
                );
                return;
            }
        };
        let _turn = SettleTurn::take(store.vault_install());
        let current = match self.current_world_kit() {
            Ok(current) => current,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "the world-kit inventory did not read; the kit pieces stay where they are"
                );
                return;
            }
        };
        settle_kit_piece(&store, confirmed, current);
        if let Err(error) = self.sweep_stale_pending_pieces(&store, current) {
            tracing::warn!(
                kind = ?error.kind(),
                "the kits a confirm replaced stay listed for the next settle's sweep"
            );
        }
    }

    /// The settle's sweep (FIX 12135): each pending piece a confirm row names
    /// is deleted, the current kit's excepted, and a kit leaves the row's list
    /// once its delete succeeds; a missing slot is a success. A kit whose
    /// delete failed stays listed. Only rows whose list shrank are written.
    fn sweep_stale_pending_pieces(
        &self,
        store: &KitPieceStore,
        current: Option<KitId>,
    ) -> Result<()> {
        let listed: Vec<(String, Vec<KitId>)> = {
            let txn = self.store.env.read_txn()?;
            KITS.scan(&self.store, &txn)?
                .into_iter()
                .filter(|(_, row)| !row.stale_pending_pieces.is_empty())
                .map(|(key, row)| (key, row.stale_pending_pieces))
                .collect()
        };
        let mut swept = Vec::new();
        for (key, kits) in listed {
            let gone: Vec<KitId> = kits
                .into_iter()
                .filter(|kit| Some(*kit) == current || drop_pending_piece(store, *kit))
                .collect();
            if !gone.is_empty() {
                swept.push((key, gone));
            }
        }
        if swept.is_empty() {
            return Ok(());
        }
        self.with_write_txn(|txn| {
            for (key, gone) in &swept {
                if let Some(mut row) = KITS.get(&self.store, txn, key)? {
                    row.stale_pending_pieces.retain(|kit| !gone.contains(kit));
                    KITS.put(&self.store, txn, key, &row)?;
                }
            }
            Ok(())
        })
    }
}

/// The settle's check and move, in the caller's turn: `confirmed`, or with
/// none `current`, the current kit as the inventory reads it now.
fn settle_kit_piece(store: &KitPieceStore, confirmed: Option<KitId>, current: Option<KitId>) {
    match confirmed {
        // A later confirm replaced it: its piece never goes over the current
        // pair, which holds the later kit's or will.
        Some(kit) if current != Some(kit) => {
            drop_pending_piece(store, kit);
        }
        _ => {
            if let Some(kit) = current
                && let Err(error) = move_pending_piece(store, kit)
            {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a confirmed world kit's piece stays in its pending kit-piece slots"
                );
            }
        }
    }
}

/// Moves the pending piece of `kit`, the current world kit, over the current
/// pair: the current pair is written before the pending pair empties, so a
/// failure between them leaves the piece in both pairs, never in neither.
fn move_pending_piece(store: &KitPieceStore, kit: KitId) -> Result<()> {
    let pending = KitPiecePair::Pending(kit);
    let Some(piece) = store.get(pending).map_err(keystore_error)? else {
        return Ok(());
    };
    store
        .put(&piece, KitPiecePair::Current(KitSecretKind::RecoveryRoot))
        .map_err(keystore_error)?;
    store.delete(pending).map_err(keystore_error)
}

/// Deletes the pending piece of `kit`, a world kit that can no longer be
/// confirmed: whether its slots are empty now. A delete that fails is logged,
/// and the piece stays.
fn drop_pending_piece(store: &KitPieceStore, kit: KitId) -> bool {
    match store.delete(KitPiecePair::Pending(kit)) {
        Ok(()) => true,
        Err(error) => {
            tracing::warn!(
                kind = ?keystore_error(error).kind(),
                "a world kit that can no longer be confirmed keeps its pending kit-piece slots"
            );
            false
        }
    }
}
