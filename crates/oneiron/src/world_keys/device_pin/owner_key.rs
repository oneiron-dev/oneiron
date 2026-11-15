//! This install's owner signing key under the device PIN (row
//! OCS-OWNER-PIN).
//!
//! On a device with a PIN set, the key's seed rests sealed under the device
//! PIN key, in the keystore's home for sealed bytes, and its
//! [`oneiron_keystore::SlotKind::OwnerSigning`] slot is empty: no copy of the
//! seed rests in the clear. The envelope shows the key's public half, so the
//! roster match needs no PIN. The seed is opened for one signature at a
//! time, only inside the window a right PIN opened, and the vault handle
//! holds no key between signatures.
//!
//! A key made before the device had a PIN rests in its slot and signs as
//! before until the next right PIN this handle sees. Then its seed is
//! sealed, read back, and its slot emptied. There is no way back: a
//! forgotten PIN is a lost key, and a fresh key is enrolled in its place.

use std::sync::{Arc, PoisonError};

use oneiron_keystore::{DeviceKeystore, KeystoreSlot};
use zeroize::Zeroizing;

use super::{
    DevicePin, DevicePinTier, device_pin_is_set, open_slot_secret, pin_refused, seal_slot_secret,
    sealed_slot_public_key,
};
use crate::authority::{
    ActAuthority, AuthorityKey, CheckpointRootSigner, HostSlipIssuer, OwnerKeyEnrollment,
    OwnerKeyEnrollmentReceipt, authority_refused,
};
use crate::entity_id::EntityId;
use crate::error::{DevicePinRefusal, Result};
use crate::vault::Vault;
use crate::world_keys::owner_signing::OwnerRootSigner;
use crate::world_keys::{keystore_error, os_fill, refused};

const OWNER_ONLY: &str = "the device PIN is the owner's to set, change and forget; no Grant \
                          action names it";
const NO_DEVICE_PIN_HERE: &str = "this host installed no device PIN on this vault";
const OTHER_KEYSTORE: &str = "the device PIN guards another keystore than this vault's";
const NO_SEALED_KEY: &str = "no owner signing key rests under the device PIN";
const SEALED_KEY_UNOPENED: &str = "the owner signing key does not open under this device's PIN \
                                   key";
const SEALED_KEY_MISNAMED: &str = "the sealed owner signing key is not the key its envelope names";
const SEAL_NOT_READ_BACK: &str = "the owner signing key sealed under the device PIN did not read \
                                  back; its slot is kept";

/// Where this install's owner signing key rests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerKeyRest {
    /// This install has no owner signing key.
    NoKey,
    /// The seed rests in its keystore slot, under no PIN: the key signs with
    /// nobody there.
    Slot,
    /// The seed rests sealed under the device PIN key: the key signs only
    /// inside the window a right PIN opened.
    DevicePin {
        /// The key's public half.
        public_key: [u8; 32],
        /// What counts wrong PINs on this device.
        tier: DevicePinTier,
    },
}

/// This install's owner signing key as a checkpoint root signer while its
/// seed rests under the device PIN. It holds the public half, never the key:
/// each signature opens the seed, signs and drops the key.
struct PinBoundOwnerSigner {
    public_key: [u8; 32],
    slot: KeystoreSlot,
    pin: Arc<DevicePin>,
}

impl PinBoundOwnerSigner {
    /// Runs `sign` with the key, opened for this one use.
    ///
    /// # Errors
    /// [`DevicePinRefusal::Required`] outside a window; a refusal for a seed
    /// that does not open, or opens to another key than its envelope names.
    fn with_key<T>(&self, sign: impl FnOnce(&OwnerRootSigner) -> T) -> Result<T> {
        let pin_key = self.pin.pin_key()?;
        let sealed = self
            .pin
            .sealed_slot(&self.slot)?
            .ok_or_else(|| refused(NO_SEALED_KEY))?;
        let seed = open_slot_secret(&pin_key, &self.slot, &self.public_key, &sealed)
            .ok_or_else(|| refused(SEALED_KEY_UNOPENED))?;
        let signer = OwnerRootSigner::from_seed(&seed);
        if signer.public_key() != self.public_key {
            return Err(refused(SEALED_KEY_MISNAMED));
        }
        Ok(sign(&signer))
    }
}

impl CheckpointRootSigner for PinBoundOwnerSigner {
    fn root(&self) -> AuthorityKey {
        AuthorityKey::Ed25519(self.public_key)
    }

    fn sign_checkpoint_statement(&self, statement: &[u8]) -> Result<Vec<u8>> {
        self.with_key(|signer| signer.sign_checkpoint_statement(statement))?
    }

    fn signs_now(&self, vault: &Vault) -> bool {
        self.pin.window_is_open() && vault.owner_key_on_live_roster(&self.public_key)
    }
}

impl Vault {
    /// Installs the process's device PIN on this handle: the host calls it
    /// after [`Vault::install_device_keystore`], with the device PIN it made
    /// over that same keystore, and before
    /// [`Vault::hold_device_owner_signer_logged`]. A host that installs none
    /// takes no PIN: on a device where one is set, it neither makes nor
    /// signs with this install's owner signing key.
    ///
    /// # Errors
    /// `KeystoreUnavailable` while no keystore is installed; a refusal for a
    /// device PIN over another keystore.
    pub fn install_device_pin(&self, pin: Arc<DevicePin>) -> Result<()> {
        let keystore = self.device_keystore()?;
        if !pin.guards(&keystore) {
            return Err(refused(OTHER_KEYSTORE));
        }
        *self
            .world_keys
            .device_pin
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(pin);
        Ok(())
    }

    /// The device PIN the host installed on this handle.
    #[must_use]
    pub fn device_pin(&self) -> Option<Arc<DevicePin>> {
        self.world_keys
            .device_pin
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// How many right PINs the device PIN on this handle took
    /// ([`DevicePin::right_pins`]); 0 where the host installed none. The
    /// device sync's steady pass brings its residence upkeep forward at each
    /// new one, so the checkpoint root exchange attests once per right PIN
    /// as well as on its interval while the window is open.
    #[must_use]
    pub fn device_pin_right_pins(&self) -> u64 {
        match self.device_pin() {
            Some(pin) => pin.right_pins(),
            None => 0,
        }
    }

    /// Where this install's owner signing key rests, read with no PIN. A
    /// host that installed no device PIN sees only the slot.
    ///
    /// # Errors
    /// `KeystoreUnavailable` while no keystore is installed; the keystore's
    /// refusal.
    pub fn device_owner_key_rest(&self) -> Result<OwnerKeyRest> {
        let keystore = self.device_keystore()?;
        let machine = self.prepare_install_signing()?;
        let slot = self.owner_signing_slot(machine);
        if let Some(pin) = self.device_pin()
            && pin.is_set()?
            && let Some(tier) = pin.tier()
            && let Some(public_key) = resting_public_key(&pin, &slot)?
        {
            return Ok(OwnerKeyRest::DevicePin { public_key, tier });
        }
        Ok(match keystore.get(&slot).map_err(keystore_error)? {
            Some(_) => OwnerKeyRest::Slot,
            None => OwnerKeyRest::NoKey,
        })
    }

    /// Sets this device's first PIN as the owner `authority` proves, and
    /// opens a window with it. This install's owner signing key, when it
    /// rests in its slot, goes under the PIN in the same call, and a key
    /// enrolled from here on is made under it. `short_pin_allowed` is the
    /// owner's choice to use a short PIN on this device
    /// ([`DevicePin::min_chars`]).
    ///
    /// # Errors
    /// An authority refusal for an agent's act, and an owner refusal when
    /// the proof is no longer the vault's live owner.
    /// [`crate::error::SecretError::DevicePin`]: `AlreadySet`, `TooShort`,
    /// and `Unavailable` where this device takes no PIN. The keystore's
    /// refusal. A key that could not go under the PIN keeps its slot and is
    /// reported.
    pub fn set_device_pin_as(
        &self,
        authority: &ActAuthority,
        pin: &[u8],
        short_pin_allowed: bool,
    ) -> Result<()> {
        let device_pin = self.device_pin_as(authority)?;
        device_pin.set(pin, short_pin_allowed)?;
        let keystore = self.device_keystore()?;
        let machine = self.prepare_install_signing()?;
        let slot = self.owner_signing_slot(machine);
        bind_slot_owner_seed(&device_pin, keystore.as_ref(), &slot)?;
        self.hold_pin_bound_owner_signer(keystore.as_ref(), &slot)?;
        Ok(())
    }

    /// Takes the device PIN the owner typed ([`DevicePin::confirm`]). A
    /// right one opens the window for every vault of this process; on this
    /// handle it also puts an owner signing key that still rests in its slot
    /// under the PIN, and holds the key for the checkpoint pass.
    ///
    /// # Errors
    /// As [`DevicePin::confirm`]; `Unavailable` where the host installed no
    /// device PIN on this handle.
    pub fn confirm_device_pin(&self, pin: &[u8]) -> Result<()> {
        self.installed_device_pin()?.confirm(pin)?;
        self.hold_device_owner_signer_logged();
        Ok(())
    }

    /// Changes this device's PIN as the owner `authority` proves: `old` is
    /// checked as any typed PIN is and counts when wrong, then the same
    /// device PIN key rests under `new`. No key is re-sealed and nothing is
    /// written to the authority log.
    ///
    /// # Errors
    /// The refusals of [`Vault::set_device_pin_as`] for the authority and
    /// for `new`; as [`DevicePin::confirm`] for `old`.
    pub fn change_device_pin_as(
        &self,
        authority: &ActAuthority,
        old: &[u8],
        new: &[u8],
        short_pin_allowed: bool,
    ) -> Result<()> {
        self.device_pin_as(authority)?
            .change(old, new, short_pin_allowed)
    }

    /// Forgets this device's PIN as the owner `authority` proves: for a PIN
    /// nobody remembers. It ends the window and removes the device PIN key
    /// and this install's sealed owner signing key. Every key that rested
    /// under the PIN is lost, in every vault of this device: there is no
    /// reset. The roster still names a lost key until it is revoked; a fresh
    /// key is enrolled in its place.
    ///
    /// # Errors
    /// The refusals of [`Vault::set_device_pin_as`] for the authority; the
    /// keystore's refusal.
    pub fn forget_device_pin_as(&self, authority: &ActAuthority) -> Result<()> {
        let device_pin = self.device_pin_as(authority)?;
        let machine = self.prepare_install_signing()?;
        let slot = self.owner_signing_slot(machine);
        let lost = resting_public_key(&device_pin, &slot)?;
        device_pin.forget()?;
        device_pin.delete_sealed_slot(&slot)?;
        if let Some(public_key) = lost {
            self.release_checkpoint_root_signer(&AuthorityKey::Ed25519(public_key));
        }
        Ok(())
    }

    /// The device PIN this install's owner signing key is made and kept
    /// under: the one on this handle, when a PIN is set on this device.
    /// `None` where no PIN is set: the key rests in its slot.
    ///
    /// # Errors
    /// [`DevicePinRefusal::Unavailable`] where a PIN is set on this device
    /// and the host installed no device PIN on this handle: such a host
    /// never makes the key in the clear beside a PIN.
    pub(in crate::world_keys) fn owner_key_device_pin(
        &self,
        keystore: &dyn DeviceKeystore,
    ) -> Result<Option<Arc<DevicePin>>> {
        if let Some(pin) = self.device_pin() {
            return Ok(pin.is_set()?.then_some(pin));
        }
        if device_pin_is_set(keystore).map_err(keystore_error)? {
            return Err(pin_refused(DevicePinRefusal::Unavailable(
                NO_DEVICE_PIN_HERE,
            )));
        }
        Ok(None)
    }

    /// The device PIN's part of [`Vault::hold_device_owner_signer_logged`].
    /// Inside a window, a seed that still rests in its slot goes under the
    /// PIN first. Then the key that rests under the PIN is held as a signer
    /// that knows only its public half, when the roster names it live.
    /// `None` when no key rests under a device PIN here: the caller reads
    /// the slot as before.
    pub(in crate::world_keys) fn hold_pin_bound_owner_signer(
        &self,
        keystore: &dyn DeviceKeystore,
        slot: &KeystoreSlot,
    ) -> Result<Option<bool>> {
        let Some(pin) = self.device_pin() else {
            return Ok(None);
        };
        if !pin.is_set()? {
            return Ok(None);
        }
        bind_slot_owner_seed(&pin, keystore, slot)?;
        let Some(public_key) = resting_public_key(&pin, slot)? else {
            return Ok(None);
        };
        let live = self
            .listed_owner_key(&public_key)?
            .is_some_and(|listed| listed.live);
        if live {
            self.hold_checkpoint_root_signer(Arc::new(PinBoundOwnerSigner {
                public_key,
                slot: *slot,
                pin,
            }));
        }
        Ok(Some(live))
    }

    /// [`Vault::enrol_device_owner_signing_key`] on a device whose PIN is
    /// set: the key is made in memory and rests only under the PIN, so the
    /// enrollment needs the window. A seed that still rests in the slot goes
    /// under the PIN first, and is the key enrolled. A sealed key that no
    /// longer opens was sealed under a PIN key this device forgot: a fresh
    /// key takes its place.
    ///
    /// # Errors
    /// [`DevicePinRefusal::Required`] outside a window; the enrollment's own
    /// refusals.
    pub(in crate::world_keys) fn enrol_pin_bound_owner_signing_key(
        &self,
        pin: Arc<DevicePin>,
        authority: &ActAuthority,
        issuer: &HostSlipIssuer,
        machine: EntityId,
        slot: KeystoreSlot,
    ) -> Result<OwnerKeyEnrollmentReceipt> {
        let pin_key = pin.pin_key()?;
        let keystore = self.device_keystore()?;
        bind_slot_owner_seed(&pin, keystore.as_ref(), &slot)?;
        let (mut seed, mut rests) = match resting_owner_seed(&pin, &pin_key, &slot)? {
            Some(seed) => (seed, true),
            None => (fresh_seed()?, false),
        };
        let mut signer = OwnerRootSigner::from_seed(&seed);
        // The owner's proof is revalidated before the roster is read.
        let mut challenge =
            self.owner_key_enrollment_challenge_as(authority, machine, &signer.public_key())?;
        match self.listed_owner_key(&signer.public_key())? {
            Some(listed) if listed.live => {
                self.hold_checkpoint_root_signer(Arc::new(PinBoundOwnerSigner {
                    public_key: listed.public_key,
                    slot,
                    pin,
                }));
                return Ok(OwnerKeyEnrollmentReceipt {
                    entry: listed.entry,
                    machine: listed.machine,
                    public_key: listed.public_key,
                });
            }
            // A revoked key is never enrolled again: a fresh seed takes its place.
            Some(_) => {
                seed = fresh_seed()?;
                rests = false;
                signer = OwnerRootSigner::from_seed(&seed);
                challenge = self.owner_key_enrollment_challenge_as(
                    authority,
                    machine,
                    &signer.public_key(),
                )?;
            }
            None => {}
        }
        let public_key = signer.public_key();
        if !rests {
            // Sealed before the enrollment is written, so a key the roster
            // names always rests here.
            let sealed = seal_slot_secret(&pin_key, &slot, &public_key, &seed)?;
            pin.put_sealed_slot(&slot, &sealed)?;
        }
        let input = OwnerKeyEnrollment {
            machine,
            public_key,
            proof: signer.sign_possession(&challenge),
        };
        let receipt = self.enrol_owner_signing_key_as_host(authority, input, issuer)?;
        self.hold_checkpoint_root_signer(Arc::new(PinBoundOwnerSigner {
            public_key,
            slot,
            pin,
        }));
        Ok(receipt)
    }

    /// The device PIN on this handle, for the owner `authority` proves,
    /// revalidated now.
    fn device_pin_as(&self, authority: &ActAuthority) -> Result<Arc<DevicePin>> {
        let owner = match authority {
            ActAuthority::Owner(owner, _) => owner,
            ActAuthority::Agent(_) => return Err(authority_refused(OWNER_ONLY)),
        };
        {
            let txn = self.store.env.read_txn()?;
            owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        }
        self.installed_device_pin()
    }

    fn installed_device_pin(&self) -> Result<Arc<DevicePin>> {
        self.device_pin()
            .ok_or_else(|| pin_refused(DevicePinRefusal::Unavailable(NO_DEVICE_PIN_HERE)))
    }
}

/// The public half of the owner signing key that rests under the device PIN
/// for `slot`, read with no key; `None` when none rests there, and for bytes
/// that are no sealed key.
fn resting_public_key(pin: &DevicePin, slot: &KeystoreSlot) -> Result<Option<[u8; 32]>> {
    Ok(pin
        .sealed_slot(slot)?
        .as_deref()
        .and_then(sealed_slot_public_key))
}

/// The owner seed that rests under the device PIN for `slot`, when one does
/// and it opens to the key its envelope names; `None` otherwise.
fn resting_owner_seed(
    pin: &DevicePin,
    pin_key: &[u8; 32],
    slot: &KeystoreSlot,
) -> Result<Option<Zeroizing<[u8; 32]>>> {
    let Some(sealed) = pin.sealed_slot(slot)? else {
        return Ok(None);
    };
    let Some(public_key) = sealed_slot_public_key(&sealed) else {
        return Ok(None);
    };
    Ok(open_slot_secret(pin_key, slot, &public_key, &sealed)
        .filter(|seed| OwnerRootSigner::from_seed(seed).public_key() == public_key))
}

/// A fresh owner seed from the OS CSPRNG, in guarded memory.
fn fresh_seed() -> Result<Zeroizing<[u8; 32]>> {
    let mut seed = Zeroizing::new([0u8; 32]);
    os_fill(&mut seed[..])?;
    Ok(seed)
}

/// Puts the owner seed that still rests in `slot` under the device PIN,
/// inside a window: sealed, read back, and only then is the slot emptied.
/// True when the slot was emptied. Outside a window, and with an empty slot,
/// nothing changes. Another key that already rests under the PIN and opens
/// stays, and the slot is left as it is.
fn bind_slot_owner_seed(
    pin: &DevicePin,
    keystore: &dyn DeviceKeystore,
    slot: &KeystoreSlot,
) -> Result<bool> {
    let Ok(pin_key) = pin.pin_key() else {
        return Ok(false);
    };
    let Some(seed) = keystore.get(slot).map_err(keystore_error)? else {
        return Ok(false);
    };
    let public_key = OwnerRootSigner::from_seed(&seed).public_key();
    if let Some(sealed) = pin.sealed_slot(slot)?
        && let Some(resting) = sealed_slot_public_key(&sealed)
        && resting != public_key
        && open_slot_secret(&pin_key, slot, &resting, &sealed).is_some()
    {
        tracing::warn!(
            "the owner signing slot holds another seed than the key under the device PIN; the \
             slot is left as it is"
        );
        return Ok(false);
    }
    let sealed = seal_slot_secret(&pin_key, slot, &public_key, &seed)?;
    pin.put_sealed_slot(slot, &sealed)?;
    let read_back = pin
        .sealed_slot(slot)?
        .and_then(|rests| open_slot_secret(&pin_key, slot, &public_key, &rests));
    if read_back.as_deref() != Some(&*seed) {
        return Err(refused(SEAL_NOT_READ_BACK));
    }
    DeviceKeystore::delete(keystore, slot).map_err(keystore_error)?;
    Ok(true)
}
