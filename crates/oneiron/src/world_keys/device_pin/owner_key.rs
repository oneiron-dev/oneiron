//! This install's owner signing key under the device PIN (row
//! OCS-OWNER-PIN).
//!
//! On a device with a PIN set, the key's seed rests sealed under the device
//! PIN key, in the keystore's home for sealed bytes, and its
//! [`oneiron_keystore::SlotKind::OwnerSigning`] slot is empty. The seed is
//! opened for one signature at a time, only inside the window a right PIN
//! opened, and the vault handle holds no key between signatures.
//!
//! Three rules hold on such a device, whatever its files look like:
//! - A seed in the slot is no key. No door reads it into a signer or makes
//!   one there, and a signer made from it before the PIN was set signs
//!   nothing more.
//! - What rests sealed proves nothing until it opens. This handle names the
//!   key's public half only after it opened the seed with the device PIN key
//!   and the seed is the one its envelope names.
//! - A signer checks the roster and the window at each signature, not only
//!   when a pass lists it.
//!
//! Setting the first PIN takes this vault's seed out of its slot in the same
//! step: the seed is sealed under the new device PIN key and read back before
//! that key is stored, and the slot is emptied before the step answers. A
//! step that fails undoes itself, and the device has no PIN, as before. A
//! process that stops between storing the device PIN key and emptying the
//! slot leaves the seed in both places; the slot's copy signs nothing, and
//! this handle's next step inside a window removes it. The same holds for
//! another vault of the device that was not open when the PIN was set.
//!
//! There is no way back: a forgotten PIN is a lost key, and a fresh key is
//! enrolled in its place.

use std::sync::{Arc, PoisonError};

use oneiron_keystore::{DeviceKeystore, KeystoreSlot, SealedBytesName};
use zeroize::Zeroizing;

use super::{
    DevicePin, DevicePinStep, DevicePinTier, device_pin_is_set, device_pin_tier, open_slot_secret,
    seal_slot_secret, sealed_slot_public_key,
};
use crate::authority::{
    ActAuthority, AuthorityKey, CheckpointRootSigner, HostSlipIssuer, OwnerKeyEnrollment,
    OwnerKeyEnrollmentReceipt, authority_refused,
};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::vault::Vault;
use crate::world_keys::owner_signing::{KEY_NOT_LIVE, OTHER_VAULT_KEY, OwnerRootSigner};
use crate::world_keys::{keystore_error, os_fill, refused};

const OWNER_ONLY: &str = "the device PIN is the owner's to set, change and forget; no Grant \
                          action names it";
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
    /// No PIN is set on this device, and the seed rests in its keystore
    /// slot: the key signs with nobody there.
    Slot,
    /// The seed rests sealed under the device PIN key, and this handle
    /// opened it with that key: the key signs only inside the window a right
    /// PIN opened.
    DevicePin {
        /// The key's public half, as the opened seed gave it.
        public_key: [u8; 32],
        /// What counts wrong PINs on this device.
        tier: DevicePinTier,
    },
    /// A PIN is set on this device, and this handle has not opened the key
    /// under it. What rests proves nothing until a right PIN opens it, so no
    /// public half is told.
    DevicePinUnopened {
        /// What counts wrong PINs on this device.
        tier: DevicePinTier,
        /// A seed still rests in the keystore slot, under no PIN. It signs
        /// nothing there. This handle's next step inside a window puts it
        /// under the PIN and empties the slot.
        seed_in_slot: bool,
    },
}

/// An owner seed opened from under the device PIN key, with the public half
/// of the key it is the seed of.
struct OpenedOwnerSeed {
    public_key: [u8; 32],
    seed: Zeroizing<[u8; 32]>,
}

/// This install's owner signing key as a checkpoint root signer while its
/// seed rests under the device PIN. It holds the public half, never the key:
/// each signature opens the seed, signs and drops the key.
struct PinBoundOwnerSigner {
    public_key: [u8; 32],
    slot: KeystoreSlot,
    pin: Arc<DevicePin>,
    /// The count of device PIN keys when the seed was opened under this one.
    key_generation: u64,
}

impl PinBoundOwnerSigner {
    /// Why the key does not sign on `vault` now, from what needs no key:
    /// `vault` is another vault's handle, the device PIN key was set or
    /// forgotten since the seed was opened, or the roster no longer lists
    /// the key live.
    fn refusal(&self, vault: &Vault) -> Option<Error> {
        if self.slot.vault_id != *vault.vault_id().as_bytes() {
            return Some(authority_refused(OTHER_VAULT_KEY));
        }
        if self.pin.key_generation() != self.key_generation {
            return Some(refused(SEALED_KEY_UNOPENED));
        }
        if !vault.owner_key_on_live_roster(&self.public_key) {
            return Some(authority_refused(KEY_NOT_LIVE));
        }
        None
    }

    /// The key's signature over the checkpoint statement `statement`.
    ///
    /// # Errors
    /// [`crate::error::DevicePinRefusal::Required`] outside a window; the refusals of
    /// [`Self::refusal`]; a refusal for a seed that does not open, or opens
    /// to another key than its envelope names.
    fn sign(&self, vault: &Vault, statement: &[u8]) -> Result<Vec<u8>> {
        if let Some(refusal) = self.refusal(vault) {
            return Err(refusal);
        }
        // Read before the key's lock is taken: a home may be slow.
        let sealed = self
            .pin
            .sealed_slot(&self.slot)?
            .ok_or_else(|| refused(NO_SEALED_KEY))?;
        // The seed is opened, used and wiped under the lock the window's end
        // takes.
        self.pin.with_pin_key(|pin_key| {
            let opened = open_owner_seed(pin_key, &self.slot, &sealed)
                .ok_or_else(|| refused(SEALED_KEY_UNOPENED))?;
            if opened.public_key != self.public_key {
                return Err(refused(SEALED_KEY_MISNAMED));
            }
            OwnerRootSigner::from_seed(&opened.seed).sign_statement(statement)
        })?
    }
}

impl CheckpointRootSigner for PinBoundOwnerSigner {
    fn root(&self) -> AuthorityKey {
        AuthorityKey::Ed25519(self.public_key)
    }

    fn sign_checkpoint_statement(&self, vault: &Vault, statement: &[u8]) -> Result<Vec<u8>> {
        self.sign(vault, statement)
    }

    fn signs_now(&self, vault: &Vault) -> bool {
        self.pin.window_is_open() && self.refusal(vault).is_none()
    }
}

impl Vault {
    /// Installs the process's device PIN on this handle: the host calls it
    /// after [`Vault::install_device_keystore`], with the device PIN it made
    /// over that same keystore, and before
    /// [`Vault::hold_device_owner_signer_logged`]. A host makes one device
    /// PIN per keystore and installs that one on every vault handle over it.
    /// A host that installs none takes no PIN: on a device where one is set,
    /// it neither makes nor signs with this install's owner signing key.
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
        // What an earlier device PIN opened counts for nothing under this one.
        self.note_pin_bound_owner_key(None);
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
    /// device sync's steady pass runs its residence upkeep once more for
    /// each new one, so the checkpoint root exchange attests after a right
    /// PIN as well as on its interval while the window is open.
    #[must_use]
    pub fn device_pin_right_pins(&self) -> u64 {
        match self.device_pin() {
            Some(pin) => pin.right_pins(),
            None => 0,
        }
    }

    /// Where this install's owner signing key rests, read with no PIN. On a
    /// device with a PIN set it names the key only when this handle opened
    /// its seed with the device PIN key: sealed bytes that were never opened
    /// here answer [`OwnerKeyRest::DevicePinUnopened`].
    ///
    /// # Errors
    /// `KeystoreUnavailable` while no keystore is installed; the keystore's
    /// refusal.
    pub fn device_owner_key_rest(&self) -> Result<OwnerKeyRest> {
        let keystore = self.device_keystore()?;
        let machine = self.prepare_install_signing()?;
        let slot = self.owner_signing_slot(machine);
        let seed_in_slot = keystore.get(&slot).map_err(keystore_error)?.is_some();
        let tier = if device_pin_is_set(keystore.as_ref()).map_err(keystore_error)? {
            device_pin_tier(keystore.as_ref())
        } else {
            None
        };
        let Some(tier) = tier else {
            return Ok(if seed_in_slot {
                OwnerKeyRest::Slot
            } else {
                OwnerKeyRest::NoKey
            });
        };
        if let Some(public_key) = self.opened_pin_bound_owner_key() {
            return Ok(OwnerKeyRest::DevicePin { public_key, tier });
        }
        Ok(
            if seed_in_slot || sealed_slot_rests(keystore.as_ref(), &slot)? {
                OwnerKeyRest::DevicePinUnopened { tier, seed_in_slot }
            } else {
                OwnerKeyRest::NoKey
            },
        )
    }

    /// Sets this device's first PIN as the owner `authority` proves, and
    /// opens a window with it. It is one step. This install's owner signing
    /// key, when it rests in its slot, is sealed under the new device PIN
    /// key and read back before that key is stored, and its slot is emptied
    /// before the step answers. A key enrolled from here on is made under
    /// the PIN. `short_pin_allowed` is the owner's choice to use a short PIN
    /// on this device ([`DevicePin::min_chars`]).
    ///
    /// A refusal undoes the step: the device has no PIN and the key rests in
    /// its slot, as before. Another vault of this device keeps its seed in
    /// its slot until its own handle's next step inside a window; from this
    /// step on that seed signs nothing.
    ///
    /// # Errors
    /// An authority refusal for an agent's act, and an owner refusal when
    /// the proof is no longer the vault's live owner.
    /// [`crate::error::SecretError::DevicePin`]: `AlreadySet`, `TooShort`,
    /// `TooManyTries` while this device takes no PIN after too many wrong
    /// ones, and `Unavailable` where this device takes no PIN. A PIN longer
    /// than 1024 bytes is refused as no passphrase an envelope takes. The
    /// keystore's refusal.
    pub fn set_device_pin_as(
        &self,
        authority: &ActAuthority,
        pin: &[u8],
        short_pin_allowed: bool,
    ) -> Result<()> {
        let owner = device_pin_owner(authority)?;
        let device_pin = self.installed_device_pin()?;
        // The step is entered before the owner's proof is read, so the proof
        // is never older than a wait for another step.
        let step = device_pin.step();
        self.revalidate_device_pin_owner(owner)?;
        device_pin.check_first_pin(&step, pin, short_pin_allowed)?;
        let keystore = self.device_keystore()?;
        let machine = self.prepare_install_signing()?;
        let slot = self.owner_signing_slot(machine);
        set_first_pin(&step, &device_pin, keystore.as_ref(), &slot, pin)?;
        self.hold_pin_bound_owner_signer(&step, &device_pin, keystore.as_ref(), &slot)?;
        Ok(())
    }

    /// Takes the device PIN the owner typed ([`DevicePin::confirm`]). A
    /// right one opens the window for every vault of this process; on this
    /// handle it also puts an owner signing key that still rests in its slot
    /// under the PIN, and opens and holds the key for the checkpoint pass.
    /// Another vault's handle does the same at its next checkpoint pass
    /// inside the window ([`Vault::hold_device_owner_signer_in_pin_window`]).
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
        let owner = device_pin_owner(authority)?;
        let device_pin = self.installed_device_pin()?;
        let step = device_pin.step();
        self.revalidate_device_pin_owner(owner)?;
        device_pin.change(&step, old, new, short_pin_allowed)
    }

    /// Forgets this device's PIN as the owner `authority` proves: for a PIN
    /// nobody remembers. It ends the window and removes the device PIN key
    /// and this install's sealed owner signing key. Every key that rested
    /// under the PIN is lost, in every vault of this device: there is no
    /// reset. The roster still names a lost key until it is revoked; a fresh
    /// key is enrolled in its place. A typed PIN that arrives meanwhile
    /// waits for this step and then finds no PIN set.
    ///
    /// # Errors
    /// The refusals of [`Vault::set_device_pin_as`] for the authority; the
    /// keystore's refusal.
    pub fn forget_device_pin_as(&self, authority: &ActAuthority) -> Result<()> {
        let owner = device_pin_owner(authority)?;
        let device_pin = self.installed_device_pin()?;
        let step = device_pin.step();
        self.revalidate_device_pin_owner(owner)?;
        let machine = self.prepare_install_signing()?;
        let slot = self.owner_signing_slot(machine);
        device_pin.forget(&step)?;
        device_pin.delete_sealed_slot(&slot)?;
        // The key this handle opened under the PIN is lost with it. What the
        // sealed bytes named is not asked: it proves nothing.
        if let Some((public_key, _)) = self.note_pin_bound_owner_key(None) {
            self.release_checkpoint_root_signer(&AuthorityKey::Ed25519(public_key));
        }
        Ok(())
    }

    /// Inside a device PIN's window, opens and holds this install's owner
    /// signing key when this handle has not opened it under the device PIN
    /// key yet. The checkpoint pass calls it before it lists its signers, so
    /// a right PIN typed through one vault serves every vault of the
    /// process, and a seed another vault left in its slot goes under the PIN
    /// in that window. Outside a window, and on a handle with no device PIN,
    /// it does nothing.
    pub fn hold_device_owner_signer_in_pin_window(&self) {
        if let Some(pin) = self.device_pin()
            && pin.window_is_open()
            && self.opened_pin_bound_owner_key().is_none()
        {
            self.hold_device_owner_signer_logged();
        }
    }

    /// The device PIN's part of [`Vault::hold_device_owner_signer_logged`],
    /// on a device with a PIN set. Inside a window, a seed that still rests
    /// in its slot is taken out of it first; then the seed under the PIN is
    /// opened, and this handle notes the key it is the seed of. Outside a
    /// window nothing under the PIN is read as a key, and what this handle
    /// opened in an earlier window stays noted. The noted key is held as a
    /// signer that knows only its public half, when the roster lists it
    /// live. True when it is held.
    pub(in crate::world_keys) fn hold_pin_bound_owner_signer(
        &self,
        step: &DevicePinStep<'_>,
        pin: &Arc<DevicePin>,
        keystore: &dyn DeviceKeystore,
        slot: &KeystoreSlot,
    ) -> Result<bool> {
        if pin.window_is_open() {
            bind_slot_owner_seed(step, pin, keystore, slot)?;
            let opened = resting_owner_seed(pin, slot)?.map(|rests| rests.public_key);
            self.note_pin_bound_owner_key(opened.map(|key| (key, pin.key_generation())));
        }
        let Some(public_key) = self.opened_pin_bound_owner_key() else {
            return Ok(false);
        };
        let live = self
            .listed_owner_key(&public_key)?
            .is_some_and(|listed| listed.live);
        if live {
            self.hold_opened_pin_bound_owner_key(pin, *slot, public_key);
        }
        Ok(live)
    }

    /// [`Vault::enrol_device_owner_signing_key`] on a device whose PIN is
    /// set: the key is made in memory and rests only under the PIN, so the
    /// enrollment needs the window. A seed that still rests in the slot goes
    /// under the PIN first, and is the key enrolled. A sealed key that no
    /// longer opens was sealed under a PIN key this device forgot: a fresh
    /// key takes its place. The caller's step covers the whole of it, so two
    /// enrollments never make two keys for one home.
    ///
    /// # Errors
    /// [`crate::error::DevicePinRefusal::Required`] outside a window; the enrollment's own
    /// refusals.
    pub(in crate::world_keys) fn enrol_pin_bound_owner_signing_key(
        &self,
        step: &DevicePinStep<'_>,
        pin: &Arc<DevicePin>,
        authority: &ActAuthority,
        issuer: &HostSlipIssuer,
        machine: EntityId,
        slot: KeystoreSlot,
    ) -> Result<OwnerKeyEnrollmentReceipt> {
        pin.require_window()?;
        let keystore = self.device_keystore()?;
        bind_slot_owner_seed(step, pin, keystore.as_ref(), &slot)?;
        let (mut seed, mut rests) = match resting_owner_seed(pin, &slot)? {
            Some(resting) => (resting.seed, true),
            None => (fresh_seed()?, false),
        };
        let mut signer = OwnerRootSigner::from_seed(&seed);
        // The owner's proof is revalidated before the roster is read.
        let mut challenge =
            self.owner_key_enrollment_challenge_as(authority, machine, &signer.public_key())?;
        match self.listed_owner_key(&signer.public_key())? {
            Some(listed) if listed.live => {
                self.hold_opened_pin_bound_owner_key(pin, slot, listed.public_key);
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
            // Sealed and read back before the enrollment is written, so a
            // key the roster names always rests here.
            seal_owner_seed(pin, &slot, &seed)?;
        }
        let input = OwnerKeyEnrollment {
            machine,
            public_key,
            proof: signer.sign_possession(&challenge),
        };
        let receipt = self.enrol_owner_signing_key_as_host(authority, input, issuer)?;
        self.hold_opened_pin_bound_owner_key(pin, slot, public_key);
        Ok(receipt)
    }

    /// Notes `public_key` as the key this handle opened under the device
    /// PIN, and holds it as a checkpoint root signer.
    fn hold_opened_pin_bound_owner_key(
        &self,
        pin: &Arc<DevicePin>,
        slot: KeystoreSlot,
        public_key: [u8; 32],
    ) {
        let key_generation = pin.key_generation();
        self.note_pin_bound_owner_key(Some((public_key, key_generation)));
        self.hold_checkpoint_root_signer(Arc::new(PinBoundOwnerSigner {
            public_key,
            slot,
            pin: Arc::clone(pin),
            key_generation,
        }));
    }

    /// The public half of the owner signing key this handle opened under
    /// the device PIN key that is set now; `None` before it opened one, and
    /// once that device PIN key was forgotten.
    fn opened_pin_bound_owner_key(&self) -> Option<[u8; 32]> {
        let (public_key, key_generation) = *self
            .world_keys
            .pin_bound_owner_key
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()?;
        let pin = self.device_pin()?;
        (pin.key_generation() == key_generation).then_some(public_key)
    }

    /// Notes what this handle opened under the device PIN: the key's public
    /// half with the count of device PIN keys it opened under, or nothing.
    /// Answers what was noted before.
    pub(in crate::world_keys) fn note_pin_bound_owner_key(
        &self,
        opened: Option<([u8; 32], u64)>,
    ) -> Option<([u8; 32], u64)> {
        std::mem::replace(
            &mut *self
                .world_keys
                .pin_bound_owner_key
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
            opened,
        )
    }

    /// The owner's proof, read against the vault now.
    fn revalidate_device_pin_owner(&self, owner: &AuthenticatedOwner) -> Result<()> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        Ok(())
    }

    fn installed_device_pin(&self) -> Result<Arc<DevicePin>> {
        self.device_pin().ok_or_else(super::no_device_pin_here)
    }
}

/// The owner whose proof `authority` carries. The device PIN is the owner's
/// alone: an agent's act is refused.
fn device_pin_owner(authority: &ActAuthority) -> Result<&AuthenticatedOwner> {
    match authority {
        ActAuthority::Owner(owner, _) => Ok(owner),
        ActAuthority::Agent(_) => Err(authority_refused(OWNER_ONLY)),
    }
}

/// Whether sealed bytes rest under `slot`'s name in `keystore`.
fn sealed_slot_rests(keystore: &dyn DeviceKeystore, slot: &KeystoreSlot) -> Result<bool> {
    match keystore.sealed_bytes() {
        Some(home) => Ok(home
            .get_sealed(&SealedBytesName::Slot(*slot))
            .map_err(keystore_error)?
            .is_some()),
        None => Ok(false),
    }
}

/// The owner seed in `sealed`, opened with the device PIN key for exactly
/// `slot`; `None` unless it opens and is the seed of the key its envelope
/// names.
fn open_owner_seed(
    pin_key: &[u8; 32],
    slot: &KeystoreSlot,
    sealed: &[u8],
) -> Option<OpenedOwnerSeed> {
    let public_key = sealed_slot_public_key(sealed)?;
    let seed = open_slot_secret(pin_key, slot, &public_key, sealed)?;
    (OwnerRootSigner::from_seed(&seed).public_key() == public_key)
        .then_some(OpenedOwnerSeed { public_key, seed })
}

/// The owner seed that rests under the device PIN for `slot`, opened inside
/// a window; `None` when none rests there, and for bytes that do not open to
/// the key they name.
///
/// # Errors
/// [`crate::error::DevicePinRefusal::Required`] outside a window; the keystore's refusal.
fn resting_owner_seed(pin: &DevicePin, slot: &KeystoreSlot) -> Result<Option<OpenedOwnerSeed>> {
    let Some(sealed) = pin.sealed_slot(slot)? else {
        return Ok(None);
    };
    pin.with_pin_key(|pin_key| open_owner_seed(pin_key, slot, &sealed))
}

/// Seals `seed` under the device PIN key for `slot`, inside a window, in
/// place of what rested there, and reads it back.
///
/// # Errors
/// [`crate::error::DevicePinRefusal::Required`] outside a window; the keystore's refusal;
/// a refusal when what then rests does not open to `seed`.
fn seal_owner_seed(pin: &DevicePin, slot: &KeystoreSlot, seed: &[u8; 32]) -> Result<()> {
    let public_key = OwnerRootSigner::from_seed(seed).public_key();
    let sealed =
        pin.with_pin_key(|pin_key| seal_slot_secret(pin_key, slot, &public_key, seed))??;
    pin.put_sealed_slot(slot, &sealed)?;
    let read_back = resting_owner_seed(pin, slot)?;
    if read_back.as_ref().map(|rests| &*rests.seed) != Some(seed) {
        return Err(refused(SEAL_NOT_READ_BACK));
    }
    Ok(())
}

/// A fresh owner seed from the OS CSPRNG, in guarded memory.
fn fresh_seed() -> Result<Zeroizing<[u8; 32]>> {
    let mut seed = Zeroizing::new([0u8; 32]);
    os_fill(&mut seed[..])?;
    Ok(seed)
}

/// The first PIN of a device, for the vault whose owner slot is `slot`: one
/// step, in the order that never leaves the device with a PIN set and no
/// sealed copy of the seed.
/// 1. The seed in the slot, when one rests there, is sealed under the new
///    device PIN key and read back ([`stage_slot_owner_seed`]).
/// 2. The device PIN key is stored under `typed`, and a window opens with
///    the key its home gave back ([`DevicePin::store_first_key`]).
/// 3. The slot is emptied.
///
/// A refusal at any point undoes what was done: the device PIN key and the
/// sealed seed are removed, and the seed is still in its slot.
fn set_first_pin(
    step: &DevicePinStep<'_>,
    pin: &DevicePin,
    keystore: &dyn DeviceKeystore,
    slot: &KeystoreSlot,
    typed: &[u8],
) -> Result<()> {
    let mut pin_key = Zeroizing::new([0u8; 32]);
    os_fill(&mut pin_key[..])?;
    let set = stage_slot_owner_seed(pin, keystore, slot, &pin_key)
        .and_then(|seed_in_slot| {
            pin.store_first_key(step, typed, &pin_key)?;
            Ok(seed_in_slot)
        })
        .and_then(|seed_in_slot| {
            if seed_in_slot {
                DeviceKeystore::delete(keystore, slot).map_err(keystore_error)?;
            }
            Ok(())
        });
    if set.is_err() {
        // Best effort. What a second refusal here leaves is the state the
        // module notes describe: a seed in a slot that signs nothing.
        let _forgotten = pin.forget(step);
        let _removed = pin.delete_sealed_slot(slot);
    }
    set
}

/// Step 1 of [`set_first_pin`], before any PIN is set: seals the seed in
/// `slot` under `pin_key`, the device PIN key about to be stored, and reads
/// it back. True when a seed rests in the slot. With an empty slot, sealed
/// bytes left under `slot`'s name are removed: no device PIN key opens them.
fn stage_slot_owner_seed(
    pin: &DevicePin,
    keystore: &dyn DeviceKeystore,
    slot: &KeystoreSlot,
    pin_key: &[u8; 32],
) -> Result<bool> {
    let Some(seed) = keystore.get(slot).map_err(keystore_error)? else {
        pin.delete_sealed_slot(slot)?;
        return Ok(false);
    };
    let public_key = OwnerRootSigner::from_seed(&seed).public_key();
    let sealed = seal_slot_secret(pin_key, slot, &public_key, &seed)?;
    pin.put_sealed_slot(slot, &sealed)?;
    let read_back = pin
        .sealed_slot(slot)?
        .and_then(|rests| open_owner_seed(pin_key, slot, &rests));
    if read_back.as_ref().map(|rests| &*rests.seed) != Some(&*seed) {
        return Err(refused(SEAL_NOT_READ_BACK));
    }
    Ok(true)
}

/// Inside a window, on a device with a PIN set, takes the seed that still
/// rests in `slot` out of it. True when the slot was emptied; outside a
/// window, and with an empty slot, nothing changes.
/// - The same seed already rests under the PIN (a set that stopped before
///   its last step): the slot is emptied.
/// - Nothing under the PIN opens: the seed is sealed and read back, then the
///   slot is emptied.
/// - Another key rests under the PIN and opens: that key is this install's.
///   No step of this engine puts a second seed in the slot of a device with
///   a PIN set, so that seed is no key of this install, and it is removed.
fn bind_slot_owner_seed(
    _step: &DevicePinStep<'_>,
    pin: &DevicePin,
    keystore: &dyn DeviceKeystore,
    slot: &KeystoreSlot,
) -> Result<bool> {
    if !pin.window_is_open() {
        return Ok(false);
    }
    let Some(seed) = keystore.get(slot).map_err(keystore_error)? else {
        return Ok(false);
    };
    match resting_owner_seed(pin, slot)? {
        Some(rests) if *rests.seed == *seed => {}
        Some(_) => tracing::warn!(
            "the owner signing slot of a device with a PIN set held another seed than the key \
             under the PIN; that seed is removed"
        ),
        None => seal_owner_seed(pin, slot, &seed)?,
    }
    DeviceKeystore::delete(keystore, slot).map_err(keystore_error)?;
    Ok(true)
}
