//! This machine's own kit pieces (FIX 1957, 2063): the piece of a kit issued with a
//! `ThisMachine` home, kept in this install's device-only key slots and never in the
//! vault store or sync.
//!
//! A piece's slot bytes (body and check, 50 bytes) span two 32-byte slots: the head
//! holds the first 32, the tail the rest and zeros. Each kit kind has its own pair, so
//! the data-key kit and the recovery-root kit each keep one piece here, and issuing
//! one replaces only its own. The two writes are not one platform operation: a pair
//! torn between two pieces fails the piece's check and reads as corrupt, never as a
//! piece.

use std::sync::Arc;

use oneiron_keystore::{DeviceKeystore, KeystoreError, KeystoreSlot, KitPieceSlot, SlotKind};
use zeroize::Zeroizing;

use super::piece::SLOT_LEN;
use super::{KitPiece, KitSecretKind};

/// One keystore slot's size.
const SLOT: usize = 32;

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

    /// Keeps `piece` as this machine's piece of its kit kind, replacing the piece
    /// an earlier kit of that kind kept. A tail that does not write after its head
    /// did empties the pair: half a piece is no piece.
    pub(crate) fn put(&self, piece: &KitPiece) -> oneiron_keystore::Result<()> {
        let [head, tail] = self.slots(piece.kind());
        let bytes = piece.slot_bytes();
        let mut head_bytes = Zeroizing::new([0u8; SLOT]);
        head_bytes.copy_from_slice(&bytes[..SLOT]);
        let mut tail_bytes = Zeroizing::new([0u8; SLOT]);
        tail_bytes[..SLOT_LEN - SLOT].copy_from_slice(&bytes[SLOT..]);
        self.write(&head, &head_bytes)?;
        if let Err(error) = self.write(&tail, &tail_bytes) {
            let _ = self.delete(piece.kind());
            return Err(error);
        }
        Ok(())
    }

    /// This machine's piece of a kit of `kind`; `None` when both its slots are
    /// empty. One half alone, a tail with bytes past the piece, and bytes that are
    /// not a piece of `kind` are `Corrupt`.
    pub(crate) fn get(&self, kind: KitSecretKind) -> oneiron_keystore::Result<Option<KitPiece>> {
        let [head, tail] = self.slots(kind);
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
            Ok(piece) if piece.kind() == kind => Ok(Some(piece)),
            _ => Err(KeystoreError::Corrupt(
                "the kit piece slots hold no piece of this kit kind",
            )),
        }
    }

    /// Empties both slots of a kit of `kind`. Empty slots are not an error.
    pub(crate) fn delete(&self, kind: KitSecretKind) -> oneiron_keystore::Result<()> {
        let [head, tail] = self.slots(kind);
        self.keystore.delete(&head)?;
        self.keystore.delete(&tail)
    }

    /// The head and tail slots of a kit of `kind`.
    fn slots(&self, kind: KitSecretKind) -> [KeystoreSlot; 2] {
        let parts = match kind {
            KitSecretKind::VaultKey => [KitPieceSlot::VaultKeyHead, KitPieceSlot::VaultKeyTail],
            KitSecretKind::RecoveryRoot => [
                KitPieceSlot::RecoveryRootHead,
                KitPieceSlot::RecoveryRootTail,
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
