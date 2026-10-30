//! This machine's own kit pieces on the vault handle (FIX 1957, 2063). Issue keeps
//! the piece of a [`PieceHome::ThisMachine`] home in this install's device-only key
//! slots and hands out the other homes' pieces; a restore here reads it back, so the
//! owner gives only the pieces still needed. The slots are named by the store's
//! vault id and this install's machine id: a restore that makes a new machine never
//! reads the piece of the install it was copied from. A world kit's draw keeps its
//! piece in the pending pair, and the piece moves to the current pair once the kit
//! is current (FIX 11977).

use crate::Vault;
use crate::error::Result;
use crate::recovery::{
    KitError, KitPassphrase, KitPiece, KitPiecePair, KitPieceStore, KitSecretKind, PieceHome,
    RestoredKitSecret, join_kept_piece, restore_kit,
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

    /// This machine's piece of a kit of `kind` in `pair`, as a restore here reads
    /// it: `None` with no keystore, no machine id yet or empty slots. Nothing is
    /// minted.
    fn kept_kit_piece(&self, kind: KitSecretKind, pair: KitPiecePair) -> Result<Option<KitPiece>> {
        let Some(store) = self.kit_piece_store_here()? else {
            return Ok(None);
        };
        store.get(kind, pair).map_err(keystore_error)
    }

    /// Whether this machine keeps its own piece of a kit of `kind` (FIX 2063), so
    /// a restore here asks the owner for one piece fewer. A piece its slots cannot
    /// give back counts as none: the owner is then asked for every piece.
    pub fn keeps_kit_piece(&self, kind: KitSecretKind) -> bool {
        matches!(self.kept_kit_piece(kind, KitPiecePair::Current), Ok(Some(_)))
    }

    /// Rebuilds a kit's secret on this machine (FIX 2063): [`restore_kit`] over
    /// `given` and this machine's own piece of the same kit when it keeps one, so
    /// the owner gives only the pieces still needed. A kept piece of another kit
    /// stays out. A piece the slots hold but cannot give back is logged and left
    /// out; when the pieces given then fall short, the refusal says so
    /// ([`KitError::KeptPieceUnreadable`]), not only that two pieces are needed.
    /// A restore the current pair's piece does not finish is tried once more with
    /// the pending pair's piece, when that piece is of another kit than the
    /// current pair's and joins `given`: a world kit whose confirm committed
    /// before its piece moved keeps it there (FIX 11977). A refusal is the first
    /// attempt's.
    pub fn restore_kit_here(
        &self,
        vault_id: [u8; 32],
        kind: KitSecretKind,
        given: &[&KitPiece],
        passphrase: Option<&KitPassphrase>,
    ) -> std::result::Result<RestoredKitSecret, KitError> {
        let current = self.kept_kit_piece(kind, KitPiecePair::Current);
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
        if restored.is_ok() {
            return restored;
        }
        let Ok(Some(pending)) = self.kept_kit_piece(kind, KitPiecePair::Pending) else {
            return restored;
        };
        let tried = matches!(&current, Ok(Some(kept)) if kept.kit_id() == pending.kit_id());
        let pieces = join_kept_piece(Some(&pending), given);
        if tried || pieces.len() == given.len() {
            return restored;
        }
        restore_kit(vault_id, kind, &pieces, passphrase).or(restored)
    }

    /// Moves a confirmed world kit's piece out of the pending pair (FIX 11977):
    /// when the pending pair holds a piece of the current world kit, that piece
    /// replaces the current pair's, then the pending pair empties. A piece of a
    /// kit still pending stays. Runs after a confirm's commit and before a draw
    /// fills the pending pair. A move that fails is logged and leaves the piece
    /// pending, where a restore here still reads it.
    pub(super) fn settle_pending_kit_piece(&self) {
        if let Err(error) = self.move_pending_kit_piece() {
            tracing::warn!(
                kind = ?error.kind(),
                "a confirmed world kit's piece stays in its pending kit-piece slots"
            );
        }
    }

    /// [`Self::settle_pending_kit_piece`]'s move: the current pair is written
    /// before the pending pair empties, so a failure between them leaves the
    /// piece in both pairs, never in neither.
    fn move_pending_kit_piece(&self) -> Result<()> {
        let kind = KitSecretKind::RecoveryRoot;
        let Some(store) = self.kit_piece_store_here()? else {
            return Ok(());
        };
        let Some(piece) = store.get(kind, KitPiecePair::Pending).map_err(keystore_error)? else {
            return Ok(());
        };
        if !self.world_kit_current(piece.kit_id())? {
            return Ok(());
        }
        store.put(&piece, KitPiecePair::Current).map_err(keystore_error)?;
        store.delete(kind, KitPiecePair::Pending).map_err(keystore_error)
    }
}

/// Issue's last step (FIX 2063): the `ThisMachine` piece goes to `pair` of `store`,
/// replacing the piece an earlier kit of its kind kept there, and the other homes'
/// pieces are what the owner is handed. A world kit's draw keeps it pending until
/// its confirm; a data-key kit, which has no confirm, keeps it current (FIX 11977).
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
