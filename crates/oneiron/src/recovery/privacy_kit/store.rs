//! This machine's own kit pieces (FIX 1957, 2063): the piece of a kit issued with a
//! `ThisMachine` home, kept in this install's device-only key slots and never in the
//! vault store or sync.
//!
//! A piece's slot bytes (body and check, 50 bytes) span two 32-byte slots: the head
//! holds the first 32, the tail the rest and zeros. Each kit kind has its own pair, so
//! the data-key kit and the recovery-root kit each keep one piece here, and issuing
//! one replaces only its own. Each world kit drawn and not yet confirmed has a pending
//! pair of its own, named by its kit id (FIX 11977, 12046): its draw keeps its piece
//! there, and its confirm moves it to the current pair, so a drawn kit the owner never
//! confirms leaves the current kit's piece and every other drawn kit's in place. A
//! data-key kit has no confirm and no pending pair. Each pending pair also names
//! its install in its own per-kit slot, cleared when that pair is removed, so a
//! sealed pre-open lookup can find a confirm's crash-left pending piece. The two
//! writes are not one platform operation: a pair torn between two pieces fails the piece's check and
//! reads as corrupt, never as a piece. Keeping a kit's current piece also names
//! this install in that kind's own slot of the vault id alone, and emptying it
//! clears that name (FIX 12054, FIX 12055): a sealed vault's pages unlock before
//! its machine id can be read, so that slot is how the unlock finds the piece
//! with no device wrap.

use std::sync::Arc;

use oneiron_keystore::{DeviceKeystore, KeystoreError, KeystoreSlot, KitPieceSlot, SlotKind};
use zeroize::Zeroizing;

use super::piece::SLOT_LEN;
use super::{KitId, KitPiece, KitSecretKind};

/// One keystore slot's size.
const SLOT: usize = 32;

/// A machine id's size: the install a slot is named for.
const INSTALL: usize = 16;

pub(crate) use crate::store::recovery_kit::KitPiecePair;

/// This install's kit-piece slots for one vault.
pub(crate) struct KitPieceStore {
    keystore: Arc<dyn DeviceKeystore>,
    vault_id: [u8; 32],
    install: [u8; 16],
}

impl KitPieceStore {
    /// The slots in `keystore` of the vault whose store id is `vault_id`, named for
    /// `install`, this install's machine id.
    pub(crate) fn new(
        keystore: Arc<dyn DeviceKeystore>,
        vault_id: [u8; 32],
        install: [u8; 16],
    ) -> Self {
        Self {
            keystore,
            vault_id,
            install,
        }
    }

    /// The vault id and machine id that name these slots.
    pub(crate) fn vault_install(&self) -> ([u8; 32], [u8; 16]) {
        (self.vault_id, self.install)
    }

    /// Keeps `piece` in `pair`, its kind's current pair or its own kit's pending
    /// pair, replacing the piece kept there. A tail that does not write after its
    /// head did empties the pair: half a piece is no piece. A current or pending
    /// pair's piece kept names this install by the vault id alone (FIX 12054, 12055).
    /// A data-key reissue overwrites its current pair in place, so an empty or
    /// already-correct install name is settled before that write: a naming failure
    /// keeps the old piece (REVIEW-4473 P1). When another install owns the name,
    /// its switch waits until the new pair is complete. Every other pair keeps
    /// write-then-name order, so settle retains its pending pair on a naming
    /// failure (REVIEW-4370 P1). An already-correct name is not rewritten.
    pub(crate) fn put(&self, piece: &KitPiece, pair: KitPiecePair) -> oneiron_keystore::Result<()> {
        let prior_install = match install_name(pair) {
            Some((slot, _)) => piece_install(&*self.keystore, &self.vault_id, slot)?,
            None => None,
        };
        let name_first = matches!(pair, KitPiecePair::Current(KitSecretKind::VaultKey))
            && !prior_install.is_some_and(|install| install != self.install);
        if name_first {
            self.name_install(pair, prior_install)?;
        }
        let [head, tail] = self.slots(pair);
        let bytes = piece.slot_bytes();
        let mut head_bytes = Zeroizing::new([0u8; SLOT]);
        head_bytes.copy_from_slice(&bytes[..SLOT]);
        let mut tail_bytes = Zeroizing::new([0u8; SLOT]);
        tail_bytes[..SLOT_LEN - SLOT].copy_from_slice(&bytes[SLOT..]);
        self.write(&head, &head_bytes)?;
        if let Err(error) = self.write(&tail, &tail_bytes) {
            let _ = self.delete(pair);
            return Err(error);
        }
        if !name_first {
            self.name_install(pair, prior_install)?;
        }
        Ok(())
    }

    /// This machine's piece in `pair`; `None` when both its slots are empty. One
    /// half alone, a tail with bytes past the piece, and bytes that are not a
    /// piece `pair` holds (another kind, or a pending pair's other kit) are
    /// `Corrupt`.
    pub(crate) fn get(&self, pair: KitPiecePair) -> oneiron_keystore::Result<Option<KitPiece>> {
        let [head, tail] = self.slots(pair);
        let (head, tail) = match (self.keystore.get(&head)?, self.keystore.get(&tail)?) {
            (None, None) => return Ok(None),
            (Some(head), Some(tail)) => (head, tail),
            _ => return Err(KeystoreError::Corrupt("half of a kit piece is missing")),
        };
        if tail[SLOT_LEN - SLOT..].iter().any(|byte| *byte != 0) {
            return Err(KeystoreError::Corrupt(
                "the kit piece's tail slot holds bytes past the piece",
            ));
        }
        let mut bytes = Zeroizing::new([0u8; SLOT_LEN]);
        bytes[..SLOT].copy_from_slice(&head[..]);
        bytes[SLOT..].copy_from_slice(&tail[..SLOT_LEN - SLOT]);
        match KitPiece::from_slot_bytes(&bytes[..]) {
            Ok(piece) if pair.holds(&piece) => Ok(Some(piece)),
            _ => Err(KeystoreError::Corrupt(
                "the kit piece slots hold no piece of this kit kind or kit",
            )),
        }
    }

    /// Empties both slots of `pair`. Empty slots are not an error. An emptied
    /// pair clears its vault-id-alone name of this install (FIX 12054, FIX 12055).
    pub(crate) fn delete(&self, pair: KitPiecePair) -> oneiron_keystore::Result<()> {
        let [head, tail] = self.slots(pair);
        self.keystore.delete(&head)?;
        self.keystore.delete(&tail)?;
        self.clear_install_name(pair);
        Ok(())
    }

    /// Names this install, in the slot of the vault id alone, as the one whose
    /// slots keep the kit's piece, once `pair`, a current or pending pair,
    /// holds it (FIX 12054, FIX 12055): a sealed vault's pages unlock before its
    /// machine id can be read, and the owner may have removed the device wrap
    /// that names this install. The name replaces another install's: the
    /// latest kept piece is the one named. A name that does not write is
    /// logged and returned: the piece stays kept in its slots, but the keep
    /// reports failed, so the caller keeps the pair it moved from (settle
    /// retains the pending pair) instead of dropping it.
    fn name_install(
        &self,
        pair: KitPiecePair,
        prior_install: Option<[u8; INSTALL]>,
    ) -> oneiron_keystore::Result<()> {
        let Some((slot, kit_kind)) = install_name(pair) else {
            return Ok(());
        };
        if prior_install == Some(self.install) {
            return Ok(());
        }
        let mut bytes = [0u8; SLOT];
        bytes[..INSTALL].copy_from_slice(&self.install);
        if let Err(error) = self.write(&install_slot(self.vault_id, slot), &bytes) {
            tracing::warn!(
                %error,
                kit_kind,
                "the vault id does not name the install that keeps the kit piece"
            );
            return Err(error);
        }
        Ok(())
    }

    /// Clears [`Self::name_install`]'s name once `pair`, a current or pending
    /// pair, is emptied, when it names this install: another install's name
    /// of its own piece stays (FIX 12054, FIX 12055). Best-effort: a name
    /// left behind names empty slots, which read as no piece.
    fn clear_install_name(&self, pair: KitPiecePair) {
        let Some((slot, kit_kind)) = install_name(pair) else {
            return;
        };
        match piece_install(&*self.keystore, &self.vault_id, slot) {
            Ok(Some(install)) if install == self.install => {}
            _ => return,
        }
        if let Err(error) = self.keystore.delete(&install_slot(self.vault_id, slot)) {
            tracing::warn!(
                %error,
                kit_kind,
                "the vault id still names an install whose kit piece is gone"
            );
        }
    }

    /// The head and tail slots of `pair`.
    fn slots(&self, pair: KitPiecePair) -> [KeystoreSlot; 2] {
        let parts = match pair {
            KitPiecePair::Current(KitSecretKind::VaultKey) => {
                [KitPieceSlot::VaultKeyHead, KitPieceSlot::VaultKeyTail]
            }
            KitPiecePair::Current(KitSecretKind::RecoveryRoot) => [
                KitPieceSlot::RecoveryRootHead,
                KitPieceSlot::RecoveryRootTail,
            ],
            KitPiecePair::Pending(kit) => [
                KitPieceSlot::RecoveryRootPendingHead(kit.0),
                KitPieceSlot::RecoveryRootPendingTail(kit.0),
            ],
        };
        parts.map(|part| KeystoreSlot {
            vault_id: self.vault_id,
            install: self.install,
            kind: SlotKind::KitPiece(part),
        })
    }

    /// One slot written: in place when filled, created when empty. A backend with
    /// no in-place update (`Unsupported`) has the slot emptied and filled again; a
    /// fill that fails then fails the issue, which hands out nothing.
    fn write(&self, slot: &KeystoreSlot, bytes: &[u8; SLOT]) -> oneiron_keystore::Result<()> {
        match self.keystore.replace(slot, bytes) {
            Ok(true) => Ok(()),
            Ok(false) => self.keystore.create(slot, bytes),
            Err(KeystoreError::Unsupported(_)) => {
                self.keystore.delete(slot)?;
                self.keystore.create(slot, bytes)
            }
            Err(error) => Err(error),
        }
    }
}

/// The machine id of the install whose slots in `keystore` keep the data-key
/// kit's piece of the vault whose store id is `vault_id`, as the vault id alone
/// names it (FIX 12054): `None` when no install is named. A slot with bytes past
/// the id is `Corrupt`.
pub(crate) fn vault_key_piece_install(
    keystore: &dyn DeviceKeystore,
    vault_id: &[u8; 32],
) -> oneiron_keystore::Result<Option<[u8; 16]>> {
    piece_install(keystore, vault_id, KitPieceSlot::VaultKeyInstall)
}

/// The machine id of the install whose slots in `keystore` keep the
/// recovery-root kit's piece of the vault whose store id is `vault_id`, as
/// the vault id alone names it (FIX 12055): the twin of
/// [`vault_key_piece_install`] for the world kit.
pub(crate) fn recovery_root_piece_install(
    keystore: &dyn DeviceKeystore,
    vault_id: &[u8; 32],
) -> oneiron_keystore::Result<Option<[u8; 16]>> {
    piece_install(keystore, vault_id, KitPieceSlot::RecoveryRootInstall)
}

/// The machine id of the install whose slots keep pending recovery-root kit
/// `kit`'s piece of the vault whose store id is `vault_id`, filed by the vault
/// id alone so the exact pending kit is discoverable before its pages open.
pub(crate) fn recovery_root_pending_piece_install(
    keystore: &dyn DeviceKeystore,
    vault_id: &[u8; 32],
    kit: KitId,
) -> oneiron_keystore::Result<Option<[u8; 16]>> {
    piece_install(
        keystore,
        vault_id,
        KitPieceSlot::RecoveryRootPendingInstall(kit.0),
    )
}

/// The install the vault-id-alone slot `slot` names for `vault_id`.
fn piece_install(
    keystore: &dyn DeviceKeystore,
    vault_id: &[u8; 32],
    slot: KitPieceSlot,
) -> oneiron_keystore::Result<Option<[u8; 16]>> {
    let Some(bytes) = keystore.get(&install_slot(*vault_id, slot))? else {
        return Ok(None);
    };
    if bytes[INSTALL..].iter().any(|byte| *byte != 0) {
        return Err(KeystoreError::Corrupt(
            "the kit piece install slot holds bytes past the install's id",
        ));
    }
    let mut install = [0u8; INSTALL];
    install.copy_from_slice(&bytes[..INSTALL]);
    Ok(Some(install))
}

/// The vault-id-alone slot naming the install that keeps `pair`'s piece, and
/// that kit kind's short name for log lines: a current pair names its kind's
/// install slot, and a pending pair names its own per-kit slot (FIX 12054,
/// FIX 12055).
fn install_name(pair: KitPiecePair) -> Option<(KitPieceSlot, &'static str)> {
    match pair {
        KitPiecePair::Current(KitSecretKind::VaultKey) => {
            Some((KitPieceSlot::VaultKeyInstall, "data-key"))
        }
        KitPiecePair::Current(KitSecretKind::RecoveryRoot) => {
            Some((KitPieceSlot::RecoveryRootInstall, "recovery-root"))
        }
        KitPiecePair::Pending(kit) => Some((
            KitPieceSlot::RecoveryRootPendingInstall(kit.0),
            "recovery-root-pending",
        )),
    }
}

/// The slot `slot` naming the install that keeps a kit piece of the vault
/// `vault_id`: filed under the all-zero install, no machine's id, so the
/// vault id alone names it.
fn install_slot(vault_id: [u8; 32], slot: KitPieceSlot) -> KeystoreSlot {
    KeystoreSlot {
        vault_id,
        install: [0; INSTALL],
        kind: SlotKind::KitPiece(slot),
    }
}

/// The pieces a restore on this machine rebuilds from (FIX 2063): `given`, then
/// `kept`, this machine's own piece, when every given piece is of its kit. A kit the
/// owner restores from other pieces (an older kit, a replaced one) never meets this
/// machine's piece of another kit.
pub(crate) fn join_kept_piece<'a>(
    kept: Option<&'a KitPiece>,
    given: &[&'a KitPiece],
) -> Vec<&'a KitPiece> {
    let mut pieces = given.to_vec();
    if let Some(kept) = kept
        && given.iter().all(|piece| piece.kit_id() == kept.kit_id())
    {
        pieces.push(kept);
    }
    pieces
}
