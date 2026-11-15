//! The Apple tiers' names: the keychain account each slot's item and each
//! sealed value's item is filed under. They are here, and not with the
//! Security framework calls, so that every platform's tests run them: the
//! calls themselves run only on an Apple device.
//!
//! A slot's account is the slot's name (OF-168). A sealed value's account is
//! its name behind a tag that no slot's name starts with. The hardware tier
//! files one more item beside its slots: the record that selects its enclave
//! key, under an account of its own. So under one keychain service a sealed
//! value shares no item with a slot or with that record, also for a slot and
//! the sealed value kept under that slot's own name.

use crate::{KeystoreSlot, SealedBytesName};

/// The account of the record that selects the hardware tier's enclave key.
/// A slot's account starts with its vault and install ids in hex, and a
/// sealed value's with the tag below, so neither is ever this one.
pub(crate) const SELECTOR_ACCOUNT: &str = "enclave-key-selector.v1";

/// What a sealed value's account starts with. A slot's name starts with its
/// vault id in hex, and `s` is no hex digit, so no slot's account starts with
/// this.
const SEALED_ACCOUNT_TAG: &str = "sealed-bytes:";

/// The account one slot's item is filed under: the slot's name.
pub(crate) fn slot_account(slot: &KeystoreSlot) -> String {
    slot.name()
}

/// The account one sealed value's item is filed under: the tag, then the
/// value's name.
pub(crate) fn sealed_account(name: &SealedBytesName) -> String {
    format!("{SEALED_ACCOUNT_TAG}{}", name.name())
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

    /// The items an Apple install already holds were filed under these two
    /// accounts, so neither may change: a slot under another account reads
    /// as empty, and a hardware tier that finds no selector record makes a
    /// new enclave key, which opens none of its stored slots.
    #[test]
    fn a_slot_and_the_enclave_key_selector_keep_the_accounts_their_stored_items_have() {
        let name = format!("{}.{}.owner-signing", "de".repeat(32), "03".repeat(16));
        assert_eq!(owner_slot().name(), name);
        assert_eq!(slot_account(&owner_slot()), name);
        assert_eq!(SELECTOR_ACCOUNT, "enclave-key-selector.v1");
    }

    #[test]
    fn a_sealed_value_shares_no_account_with_a_slot_the_selector_or_another_value() {
        let slot_accounts: BTreeSet<String> = slots().iter().map(slot_account).collect();
        let sealed_accounts: BTreeSet<String> = sealed_names().iter().map(sealed_account).collect();
        assert_eq!(
            sealed_accounts.len(),
            sealed_names().len(),
            "two sealed values share an account"
        );
        for account in &sealed_accounts {
            assert!(
                !slot_accounts.contains(account),
                "the sealed value's account {account} is a slot's: its item would read as that slot"
            );
            assert_ne!(
                account.as_str(),
                SELECTOR_ACCOUNT,
                "a sealed value's account is the enclave key selector's"
            );
        }
        // Why none can ever match: a slot's account starts with a hex digit of
        // its vault id, and a sealed value's with the tag, whose first letter
        // is no hex digit and which the selector's account does not start with.
        assert!(slot_accounts.iter().all(|account| {
            account
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_hexdigit)
        }));
        assert!(
            sealed_accounts
                .iter()
                .all(|account| account.starts_with("sealed-bytes:"))
        );
        assert!(!SELECTOR_ACCOUNT.starts_with("sealed-bytes:"));
        assert_eq!(
            sealed_account(&SealedBytesName::DevicePinKey),
            "sealed-bytes:device-pin-key"
        );
        assert_eq!(
            sealed_account(&SealedBytesName::Slot(owner_slot())),
            format!("sealed-bytes:{}", owner_slot().name())
        );
    }
}
