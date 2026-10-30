//! This machine's own kit pieces on the vault handle (FIX 1957, 2063). Issue keeps
//! the piece of a [`PieceHome::ThisMachine`] home in this install's device-only key
//! slots and hands out the other homes' pieces; a restore here reads it back, so the
//! owner gives only the pieces still needed. The slots are named by the store's
//! vault id and this install's machine id: a restore that makes a new machine never
//! reads the piece of the install it was copied from.

use crate::Vault;
use crate::error::Result;
use crate::recovery::{
    KitError, KitPassphrase, KitPiece, KitPieceStore, KitSecretKind, PieceHome, RestoredKitSecret,
    join_kept_piece, restore_kit,
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

    /// This machine's piece of a kit of `kind`, as a restore here reads it: `None`
    /// with no keystore, no machine id yet or empty slots. Nothing is minted.
    fn kept_kit_piece(&self, kind: KitSecretKind) -> Result<Option<KitPiece>> {
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
        KitPieceStore::new(keystore, *self.vault_id().as_bytes(), *install.as_bytes())
            .get(kind)
            .map_err(keystore_error)
    }

    /// Whether this machine keeps its own piece of a kit of `kind` (FIX 2063), so
    /// a restore here asks the owner for one piece fewer. A piece its slots cannot
    /// give back counts as none: the owner is then asked for every piece.
    pub fn keeps_kit_piece(&self, kind: KitSecretKind) -> bool {
        matches!(self.kept_kit_piece(kind), Ok(Some(_)))
    }

    /// Rebuilds a kit's secret on this machine (FIX 2063): [`restore_kit`] over
    /// `given` and this machine's own piece of the same kit when it keeps one, so
    /// the owner gives only the pieces still needed. A kept piece of another kit
    /// stays out. A piece the slots hold but cannot give back is logged and left
    /// out; when the pieces given then fall short, the refusal says so
    /// ([`KitError::KeptPieceUnreadable`]), not only that two pieces are needed.
    pub fn restore_kit_here(
        &self,
        vault_id: [u8; 32],
        kind: KitSecretKind,
        given: &[&KitPiece],
        passphrase: Option<&KitPassphrase>,
    ) -> std::result::Result<RestoredKitSecret, KitError> {
        match self.kept_kit_piece(kind) {
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
        }
    }
}

/// Issue's last step (FIX 2063): the `ThisMachine` piece goes to `store`, replacing
/// the piece an earlier kit of its kind kept there, and the other homes' pieces are
/// what the owner is handed. With no `store` the kit has no `ThisMachine` home, and
/// the pieces pass as they are.
pub(super) fn keep_this_machine_piece(
    store: Option<&KitPieceStore>,
    pieces: Vec<KitPiece>,
) -> Result<Vec<KitPiece>> {
    let Some(store) = store else {
        return Ok(pieces);
    };
    let mut handed = Vec::with_capacity(pieces.len());
    for piece in pieces {
        if piece.home() == Some(&PieceHome::ThisMachine) {
            store.put(&piece).map_err(keystore_error)?;
        } else {
            handed.push(piece);
        }
    }
    Ok(handed)
}
