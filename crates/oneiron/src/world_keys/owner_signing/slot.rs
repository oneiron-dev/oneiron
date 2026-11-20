//! An install's owner signing slot ([`Vault::device_owner_signing_slot`])
//! and the renewal of its seed by a door that makes a new owner signing key:
//! a root appointment's successor, or the recovery root's door's fresh key
//! (FIX APPOINTMENT-DROPS-SLOT-SEED-BEFORE-ITS-VERDICT). The new key is made
//! in memory, and the slot takes its seed only once the door's writer has
//! judged and stored the rows that name it, as the last step before the
//! commit. A door refused before that leaves the slot's seed as it was.
//!
//! [`Vault::device_owner_signing_slot`]: crate::Vault::device_owner_signing_slot

use std::sync::Arc;

use oneiron_keystore::{DeviceKeystore, KeystoreError, KeystoreSlot};
use zeroize::Zeroizing;

use super::{OwnerRootSigner, SEED_LEFT_ITS_SLOT, slot_keys_allowed, slot_owner_signer};
use crate::error::Result;
use crate::world_keys::{keystore_error, os_fill, refused};

/// An install's owner signing slot.
pub(crate) struct OwnerSigningSlot {
    pub(super) keystore: Arc<dyn DeviceKeystore>,
    pub(super) slot: KeystoreSlot,
}

/// A new owner signing key made in memory from the OS CSPRNG, whose seed no
/// slot holds yet ([`OwnerSigningSlot::fresh_key`]). Its signer signs the
/// rows that name it; it is held as this install's key only once the slot
/// takes its seed ([`OwnerSigningSlot::renew`]).
pub(crate) struct FreshOwnerKey {
    seed: Zeroizing<[u8; 32]>,
    signer: OwnerRootSigner,
}

impl FreshOwnerKey {
    /// The new key's signer, read from no slot.
    pub(crate) fn signer(&self) -> &OwnerRootSigner {
        &self.signer
    }
}

/// What [`OwnerSigningSlot::renew`] replaced: the seed the slot held, or
/// none, kept until the door knows whether its commit landed.
pub(crate) struct SlotRenewal {
    successor: [u8; 32],
    replaced: Option<Zeroizing<[u8; 32]>>,
}

impl SlotRenewal {
    /// The public half of the key the slot took.
    pub(crate) fn successor(&self) -> [u8; 32] {
        self.successor
    }
}

impl OwnerSigningSlot {
    /// The slot's owner signing key, its seed made on first use. The roster
    /// may name it, live or revoked. Refused on a device with a PIN set or
    /// forgotten, as [`Self::fresh_key`] is (`slot_owner_signer`'s rule).
    ///
    /// # Errors
    /// The keystore's own refusal; the slot's rule.
    pub(crate) fn key(&self) -> Result<OwnerRootSigner> {
        slot_owner_signer(&self.keystore, &self.slot)
    }

    /// A new owner signing key for this slot, made in memory from the OS
    /// CSPRNG: a key no row names, never the slot's existing key, which the
    /// roster may name, live or revoked. The slot keeps its seed until the
    /// door renews it ([`Self::renew`]). A door makes it in its writer once
    /// the roster reads rootless there (the appointment) or reads the slot's
    /// key revoked there (the recovery root's door): a run checked before
    /// another run's write committed is refused first.
    ///
    /// Refused on a device with a PIN set or forgotten (`slot_owner_signer`'s
    /// rule; ruling ANCHOR-SUCCESSOR-ON-PIN-DEVICE = A): there a seed in the
    /// slot is no key, and one that still waits to go under the PIN is not
    /// dropped. The appointment and the recovery root's door hold the device
    /// PIN's step from before their writer to the commit, so no PIN of this
    /// process is set between this check and the commit.
    ///
    /// # Errors
    /// The OS CSPRNG's failure; the slot's rule, as
    /// [`crate::Vault::device_owner_signing_key`] answers it.
    pub(crate) fn fresh_key(&self) -> Result<FreshOwnerKey> {
        slot_keys_allowed(self.keystore.as_ref())?;
        let mut seed = Zeroizing::new([0u8; 32]);
        os_fill(&mut seed[..])?;
        let signer = OwnerRootSigner::from_seed(&seed);
        Ok(FreshOwnerKey { seed, signer })
    }

    /// Puts `fresh`'s seed in this slot in place of the seed it holds, and
    /// answers `fresh`'s key as read back from the slot (it signs while the
    /// slot holds its seed) with what the slot held before. The door holds
    /// the vault's `owner_signing_slot_lock` from before its writer to its
    /// commit, so no other door of this process reads or renews the slot in
    /// between: each takes that lock, the get-only readers
    /// `hold_device_owner_signer` and `device_owner_key_rest` too (FIX
    /// OWNER-SLOT-GET-ONLY-READERS-SEE-RENEWAL-GAP).
    ///
    /// # Errors
    /// The slot's rule; the keystore's own refusal; another seed in the
    /// emptied slot (a process with no share in this lock). The slot then
    /// takes back the seed it held, where it still holds `fresh`'s or none.
    pub(crate) fn renew(&self, fresh: &FreshOwnerKey) -> Result<(OwnerRootSigner, SlotRenewal)> {
        slot_keys_allowed(self.keystore.as_ref())?;
        let renewal = SlotRenewal {
            successor: fresh.signer.public_key(),
            replaced: self.keystore.get(&self.slot).map_err(keystore_error)?,
        };
        let renewed = DeviceKeystore::delete(self.keystore.as_ref(), &self.slot)
            .and_then(|()| self.keystore.create(&self.slot, &fresh.seed))
            .map_err(keystore_error)
            .and_then(|()| slot_owner_signer(&self.keystore, &self.slot));
        match renewed {
            Ok(key) if key.public_key() == renewal.successor => Ok((key, renewal)),
            Ok(_) => {
                self.put_back(renewal);
                Err(refused(SEED_LEFT_ITS_SLOT))
            }
            Err(error) => {
                self.put_back(renewal);
                Err(error)
            }
        }
    }

    /// The slot takes back the seed `renewal` replaced, for a door whose
    /// renewal or commit failed: only while the slot holds the successor's
    /// seed or none, so a seed another process put there stays. A keystore
    /// failure here is logged by kind, and the slot keeps what it holds.
    pub(crate) fn put_back(&self, renewal: SlotRenewal) {
        let holds_successor = match self.keystore.get(&self.slot) {
            Ok(Some(seed)) => OwnerRootSigner::from_seed(&seed).public_key() == renewal.successor,
            Ok(None) => true,
            Err(error) => return log_not_put_back(error),
        };
        if !holds_successor {
            return;
        }
        let restored = DeviceKeystore::delete(self.keystore.as_ref(), &self.slot).and_then(|()| {
            renewal
                .replaced
                .as_ref()
                .map_or(Ok(()), |seed| self.keystore.create(&self.slot, seed))
        });
        if let Err(error) = restored {
            log_not_put_back(error);
        }
    }
}

/// A put-back that failed, by kind only.
fn log_not_put_back(error: KeystoreError) {
    tracing::warn!(
        kind = ?keystore_error(error).kind(),
        "this install's owner signing slot did not take back its old seed after a refused renewal"
    );
}
