//! The Windows tier's names: the file each slot and each sealed value rests
//! in, and the extra entropy DPAPI seals it with. They are here, and not with
//! the DPAPI calls, so that every platform's tests run them: the calls
//! themselves run only on Windows.
//!
//! A slot's file is `<slot name>.dpapi` and its entropy is the slot's name
//! (OF-168). A sealed value's file is `<name>.sealed`, and its entropy is its
//! name behind a tag that no slot's name starts with. So a sealed value shares
//! no file with a slot, and neither one's file opens as the other, also for a
//! slot and the sealed value kept under that slot's own name.

use crate::{KeystoreSlot, SealedBytesName};

/// What a sealed value's entropy starts with. A slot's name starts with its
/// vault id in hex, and `s` is no hex digit, so no slot's entropy starts with
/// this.
const SEALED_ENTROPY_TAG: &str = "sealed-bytes:";

/// The file of one slot in the key directory.
pub(crate) fn slot_file_name(slot: &KeystoreSlot) -> String {
    format!("{}.dpapi", slot.name())
}

/// The extra entropy one slot's file is sealed with: the slot's name.
pub(crate) fn slot_entropy(slot: &KeystoreSlot) -> Vec<u8> {
    slot.name().into_bytes()
}

/// The file of one sealed value in the key directory, under a suffix no slot
/// file has.
pub(crate) fn sealed_file_name(name: &SealedBytesName) -> String {
    format!("{}.sealed", name.name())
}

/// The extra entropy one sealed value's file is sealed with: the tag, then
/// the value's name.
pub(crate) fn sealed_entropy(name: &SealedBytesName) -> Vec<u8> {
    format!("{SEALED_ENTROPY_TAG}{}", name.name()).into_bytes()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::{KitPieceSlot, SlotKind};

    /// One slot of each shape a slot's label has (a fixed word, and a word
    /// with an id after it), all of one vault and one install.
    fn slots() -> Vec<KeystoreSlot> {
        [
            SlotKind::MachineEncryption,
            SlotKind::DeviceSigning,
            SlotKind::VaultUnlock,
            SlotKind::CheckpointSigning,
            SlotKind::HostRoot,
            SlotKind::HostIssuerSeed,
            SlotKind::OwnerSigning,
            SlotKind::KitPiece(KitPieceSlot::VaultKeyHead),
            SlotKind::KitPiece(KitPieceSlot::RecoveryRootPendingTail([0xab; 4])),
            SlotKind::LegalCloneOrder([0xcd; 16]),
        ]
        .into_iter()
        .map(|kind| KeystoreSlot {
            vault_id: [0xde; 32],
            install: [3; 16],
            kind,
        })
        .collect()
    }

    /// The device PIN key's name, and the name of each slot's sealed value.
    fn sealed_names() -> Vec<SealedBytesName> {
        std::iter::once(SealedBytesName::DevicePinKey)
            .chain(slots().into_iter().map(SealedBytesName::Slot))
            .collect()
    }

    fn owner_slot() -> KeystoreSlot {
        KeystoreSlot {
            vault_id: [0xde; 32],
            install: [3; 16],
            kind: SlotKind::OwnerSigning,
        }
    }

    /// The slot files a Windows install already holds were written under
    /// these two names, so neither may change: a slot under another file
    /// name reads as empty, and one under another entropy does not open.
    #[test]
    fn a_slot_keeps_the_file_name_and_the_entropy_its_stored_file_was_sealed_with() {
        let name = format!("{}.{}.owner-signing", "de".repeat(32), "03".repeat(16));
        assert_eq!(owner_slot().name(), name);
        assert_eq!(slot_file_name(&owner_slot()), format!("{name}.dpapi"));
        assert_eq!(slot_entropy(&owner_slot()), name.into_bytes());
    }

    #[test]
    fn a_sealed_value_shares_no_file_with_a_slot_or_with_another_value() {
        let slot_files: BTreeSet<String> = slots().iter().map(slot_file_name).collect();
        let sealed_files: BTreeSet<String> = sealed_names().iter().map(sealed_file_name).collect();
        assert_eq!(
            sealed_files.len(),
            sealed_names().len(),
            "two sealed values share a file"
        );
        for file in &sealed_files {
            assert!(
                !slot_files.contains(file),
                "the sealed value's file {file} is a slot's file"
            );
        }
        assert_eq!(
            sealed_file_name(&SealedBytesName::DevicePinKey),
            "device-pin-key.sealed"
        );
        assert_eq!(
            sealed_file_name(&SealedBytesName::Slot(owner_slot())),
            format!("{}.sealed", owner_slot().name())
        );
    }

    #[test]
    fn a_sealed_value_s_entropy_opens_no_slot_and_no_other_value() {
        let slot_entropies: BTreeSet<Vec<u8>> = slots().iter().map(slot_entropy).collect();
        let sealed_entropies: BTreeSet<Vec<u8>> =
            sealed_names().iter().map(sealed_entropy).collect();
        assert_eq!(
            sealed_entropies.len(),
            sealed_names().len(),
            "two sealed values share an entropy"
        );
        for entropy in &sealed_entropies {
            assert!(
                !slot_entropies.contains(entropy),
                "a sealed value's entropy is a slot's: its file would open as that slot"
            );
        }
        // Why none can ever match: a slot's entropy starts with a hex digit of
        // its vault id, and a sealed value's with the tag's first letter.
        assert!(
            slot_entropies
                .iter()
                .all(|entropy| entropy.first().is_some_and(u8::is_ascii_hexdigit))
        );
        assert!(sealed_entropies.iter().all(|entropy| {
            entropy
                .first()
                .is_some_and(|first| !first.is_ascii_hexdigit())
        }));
        assert_eq!(
            sealed_entropy(&SealedBytesName::DevicePinKey),
            b"sealed-bytes:device-pin-key"
        );
        assert_eq!(
            sealed_entropy(&SealedBytesName::Slot(owner_slot())),
            format!("sealed-bytes:{}", owner_slot().name()).into_bytes()
        );
    }
}
