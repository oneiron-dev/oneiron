//! This machine's own kit pieces on the vault handle (FIX 1957, 2063). Issue keeps
//! the piece of a [`PieceHome::ThisMachine`] home in this install's device-only key
//! slots and hands out the other homes' pieces; a restore here reads it back, so the
//! owner gives only the pieces still needed. The slots are named by the store's
//! vault id and this install's machine id: a restore that makes a new machine never
//! reads the piece of the install it was copied from. A world kit's draw keeps its
//! piece in that kit's own pending pair, and the piece moves to the current pair
//! once the kit is current (FIX 11977, 12046): each drawn kit keeps its own until
//! its confirm.

use crate::Vault;
use crate::error::Result;
use crate::recovery::{
    KitError, KitId, KitManifest, KitPassphrase, KitPiece, KitPiecePair, KitPieceStore,
    KitSecretKind, PieceHome, RestoredKitSecret, join_kept_piece, restore_kit,
};

use super::keystore_error;

impl Vault {
    /// Where a kit issued over `homes` keeps this machine's piece: `None` with no
    /// `ThisMachine` home, the keystore untouched. With one, this install's slots,
    /// its machine id minted when it has none, as every slot's name needs it.
    /// Refused `KeystoreUnavailable` while the host installed no keystore, before
    /// any kit is drawn.
    pub(super) fn this_machine_piece_store(
        &self,
        homes: &[PieceHome; 3],
    ) -> Result<Option<KitPieceStore>> {
        if !homes.contains(&PieceHome::ThisMachine) {
            return Ok(None);
        }
        let keystore = self.device_keystore()?;
        let install = self.prepare_install_signing()?;
        Ok(Some(KitPieceStore::new(
            keystore,
            *self.vault_id().as_bytes(),
            *install.as_bytes(),
        )))
    }

    /// This install's kit-piece slots as they stand: `None` with no keystore or
    /// no machine id yet. Nothing is minted.
    fn kit_piece_store_here(&self) -> Result<Option<KitPieceStore>> {
        let Ok(keystore) = self.device_keystore() else {
            return Ok(None);
        };
        let install = {
            let txn = self.store.env.read_txn()?;
            crate::identity::read_machine_id_in_txn(self, &txn)?
        };
        let Some(install) = install else {
            return Ok(None);
        };
        Ok(Some(KitPieceStore::new(
            keystore,
            *self.vault_id().as_bytes(),
            *install.as_bytes(),
        )))
    }

    /// This machine's piece in `pair`, as a restore here reads it: `None` with
    /// no keystore, no machine id yet or empty slots. Nothing is minted.
    fn kept_kit_piece(&self, pair: KitPiecePair) -> Result<Option<KitPiece>> {
        let Some(store) = self.kit_piece_store_here()? else {
            return Ok(None);
        };
        store.get(pair).map_err(keystore_error)
    }

    /// Whether this machine keeps its own piece of a kit of `kind` (FIX 2063), so
    /// a restore here asks the owner for one piece fewer. A piece its slots cannot
    /// give back counts as none: the owner is then asked for every piece.
    pub fn keeps_kit_piece(&self, kind: KitSecretKind) -> bool {
        matches!(
            self.kept_kit_piece(KitPiecePair::Current(kind)),
            Ok(Some(_))
        )
    }

    /// Rebuilds a kit's secret on this machine (FIX 2063): [`restore_kit`] over
    /// `given` and this machine's own piece of the same kit when it keeps one, so
    /// the owner gives only the pieces still needed. A kept piece of another kit
    /// stays out. A piece the slots hold but cannot give back is logged and left
    /// out; when the pieces given then fall short, the refusal says so
    /// ([`KitError::KeptPieceUnreadable`]), not only that two pieces are needed.
    /// A world-kit restore the current pair's piece does not finish is tried
    /// once more with the pending piece of the kit `given` names, by kit id, or
    /// with none given, of the current world kit, when that kit is not the
    /// current pair's: a drawn kit keeps its piece in its own pending pair until
    /// its confirm moves it (FIX 11977, 12046). A refusal is the first attempt's.
    pub fn restore_kit_here(
        &self,
        vault_id: [u8; 32],
        kind: KitSecretKind,
        given: &[&KitPiece],
        passphrase: Option<&KitPassphrase>,
    ) -> std::result::Result<RestoredKitSecret, KitError> {
        let current = self.kept_kit_piece(KitPiecePair::Current(kind));
        let restored = match &current {
            Ok(kept) => restore_kit(
                vault_id,
                kind,
                &join_kept_piece(kept.as_ref(), given),
                passphrase,
            ),
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "this machine's kit piece did not read; restoring from the pieces given"
                );
                restore_kit(vault_id, kind, given, passphrase).map_err(|error| match error {
                    KitError::NeedTwoPieces => KitError::KeptPieceUnreadable,
                    error => error,
                })
            }
        };
        if restored.is_ok() || kind != KitSecretKind::RecoveryRoot {
            return restored;
        }
        let Some(kit) = self.pending_kit_named(given) else {
            return restored;
        };
        if matches!(&current, Ok(Some(kept)) if kept.kit_id() == kit) {
            return restored;
        }
        let Ok(Some(pending)) = self.kept_kit_piece(KitPiecePair::Pending(kit)) else {
            return restored;
        };
        let pieces = join_kept_piece(Some(&pending), given);
        restore_kit(vault_id, kind, &pieces, passphrase).or(restored)
    }

    /// The world kit whose pending piece a restore here reads (FIX 12046): the
    /// one kit every given piece names, or with none given, the current world
    /// kit as this install's inventory reads it. Pieces of two kits name none.
    fn pending_kit_named(&self, given: &[&KitPiece]) -> Option<KitId> {
        let Some(first) = given.first() else {
            return self.current_world_kit().ok().flatten();
        };
        let kit = first.kit_id();
        given
            .iter()
            .all(|piece| piece.kit_id() == kit)
            .then_some(kit)
    }

    /// Settles this install's world-kit pieces (FIX 11977, 12046): the current
    /// world kit's pending piece, when it has one, replaces the current pair's,
    /// then its pending pair empties, and the pending pieces of the kits in
    /// `replaced`, which can no longer be confirmed, are deleted. The piece of a
    /// kit still pending stays, whatever kit became current. Runs after a
    /// confirm's commit, with the kits it replaced, and before a draw keeps its
    /// piece, with none. A step that fails is logged and leaves its piece where
    /// it is, where a restore here still reads it.
    pub(super) fn settle_pending_kit_pieces(&self, replaced: &[KitId]) {
        if let Err(error) = self.move_pending_kit_piece() {
            tracing::warn!(
                kind = ?error.kind(),
                "a confirmed world kit's piece stays in its pending kit-piece slots"
            );
        }
        for kit in replaced {
            self.drop_pending_kit_piece(*kit);
        }
    }

    /// [`Self::settle_pending_kit_pieces`]'s move: the current pair is written
    /// before the pending pair empties, so a failure between them leaves the
    /// piece in both pairs, never in neither.
    fn move_pending_kit_piece(&self) -> Result<()> {
        let Some(store) = self.kit_piece_store_here()? else {
            return Ok(());
        };
        let Some(kit) = self.current_world_kit()? else {
            return Ok(());
        };
        let pending = KitPiecePair::Pending(kit);
        let Some(piece) = store.get(pending).map_err(keystore_error)? else {
            return Ok(());
        };
        store
            .put(&piece, KitPiecePair::Current(KitSecretKind::RecoveryRoot))
            .map_err(keystore_error)?;
        store.delete(pending).map_err(keystore_error)
    }

    /// A drawn world kit whose pending row did not commit (FIX 12046): no
    /// confirm can take it, so the piece its `ThisMachine` home kept pending
    /// goes.
    pub(super) fn drop_unlisted_kit_piece(&self, manifest: &KitManifest) {
        if manifest.homes.contains(&PieceHome::ThisMachine) {
            self.drop_pending_kit_piece(manifest.kit_id);
        }
    }

    /// Deletes this install's pending piece of the world kit `kit` (FIX 12046),
    /// best-effort: a delete that fails is logged, and the piece stays.
    fn drop_pending_kit_piece(&self, kit: KitId) {
        let dropped = self.kit_piece_store_here().and_then(|store| match store {
            Some(store) => store
                .delete(KitPiecePair::Pending(kit))
                .map_err(keystore_error),
            None => Ok(()),
        });
        if let Err(error) = dropped {
            tracing::warn!(
                kind = ?error.kind(),
                "a world kit that can no longer be confirmed keeps its pending kit-piece slots"
            );
        }
    }
}

/// Issue's last step (FIX 2063): the `ThisMachine` piece goes to `pair` of `store`,
/// replacing the piece kept there, and the other homes' pieces are what the owner
/// is handed. A world kit's draw keeps it in that kit's own pending pair until its
/// confirm; a data-key kit, which has no confirm, keeps it in its kind's current
/// pair (FIX 11977, 12046).
/// With no `store` the kit has no `ThisMachine` home, and the pieces pass as they
/// are.
pub(super) fn keep_this_machine_piece(
    store: Option<&KitPieceStore>,
    pair: KitPiecePair,
    pieces: Vec<KitPiece>,
) -> Result<Vec<KitPiece>> {
    let Some(store) = store else {
        return Ok(pieces);
    };
    let mut handed = Vec::with_capacity(pieces.len());
    for piece in pieces {
        if piece.home() == Some(&PieceHome::ThisMachine) {
            store.put(&piece, pair).map_err(keystore_error)?;
        } else {
            handed.push(piece);
        }
    }
    Ok(handed)
}
