//! This install's own owner signing key (FIX 4921; owner ruling 10-19,
//! OWNER SIGNING KEYS = B): one Ed25519 key per install and vault, whose seed
//! rests in the device keystore's [`SlotKind::OwnerSigning`] slot, Software
//! tier (a hardware key is a later line). The owner's enrollment act puts its
//! public half on the roster as an owner root of its own (FIX 4920); nothing
//! enrols it on its own. Once enrolled, the vault handle holds it as a
//! checkpoint root signer ([`Vault::hold_checkpoint_root_signer`]): where the
//! vault opens with its keystore, and right after the enrollment. So the
//! device sync's steady pass attests the home's checkpoint images with it,
//! and the host's intake takes them, with the home machine off. The quorum
//! the policy counts, and the rule that a received checkpoint never picks
//! its signers, stay as they are.
//!
//! The key signs checkpoint statements alone, a key binding's or an
//! attestation's: a raw 64-byte Ed25519 signature over `domain || msgpack`.
//! Its one other signature is the enrollment's proof of possession, made in
//! this module. The seed is read from its home into guarded memory, the key
//! is wiped on drop, and neither leaves this install.
//!
//! With `[keystore] backend = "off"` this install holds no device keys, so it
//! has no owner signing key either (FIX 843, Engine 21:35): the explicit home
//! for a host-held key is the platform backend, never a file beside the vault.
//!
//! On a device with a PIN set (row OCS-OWNER-PIN) the seed rests sealed under
//! the device PIN key and the slot is empty: the key is made, kept and held
//! by `device_pin::owner_key`, and it signs only inside the window a right
//! PIN opened. A seed in the slot is no key there: no door of this module
//! reads it or makes one, and a signer made from the slot before the PIN was
//! set signs nothing more. The same holds once a PIN of the device was
//! forgotten, with a PIN set or with none: every key the device held was
//! lost with that PIN, and its next key is made under a new one. A signer
//! made from a slot also signs only while that slot still holds its seed,
//! and it reads the slot at each signature: while the slot is empty or holds
//! another seed, a seed that a PIN took under itself, or that a forget or a
//! fresh key removed, leaves no signer behind, whatever the keystore says
//! about its PIN afterwards. Known limit: a copy of the slot's stored form
//! that someone kept from before the PIN brings the key back with no PIN,
//! once it is put back and the device PIN key, or the mark of a forgotten
//! PIN, is removed; so does a key directory restored from before the PIN. A
//! PIN added to a key does not undo an earlier copy of that key. Renewing
//! the key does (row DEVICE-PIN-ADD-ROTATES-OWNER-KEY). Either way, a key
//! signs only while the roster lists it live, and it checks that at each
//! signature.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron_keystore::{DeviceKeystore, KeystoreSlot, SlotKind};

use super::DevicePin;
use super::device_pin::{
    SlotSeedBar, device_pin_is_set, no_device_pin_here, pin_refused, slot_seed_bar,
};
use crate::authority::{
    ActAuthority, AuthorityKey, CheckpointRootSigner, EnrolledOwnerKey, HostSlipIssuer,
    OwnerKeyEnrollment, OwnerKeyEnrollmentReceipt, authority_refused, checkpoint_statement_domain,
    invalid_authority,
};
use crate::entity_id::EntityId;
use crate::error::{DevicePinRefusal, Error, Result};
use crate::vault::Vault;

/// The context the signing key is derived under from its seed.
const OWNER_SIGNING_CONTEXT: &str = "oneiron/owner-signing-key/v1";

const KEPT_UNDER_DEVICE_PIN: &str = "this install's owner signing key is kept under the device \
                                     PIN and is not handed out";
const LOST_WITH_FORGOTTEN_PIN: &str = "this owner signing key was lost with the device PIN that \
                                       was forgotten";
const SEED_LEFT_ITS_SLOT: &str = "this owner signing key's seed no longer rests in its keystore \
                                  slot";
pub(super) const KEY_NOT_LIVE: &str = "the roster does not list this owner signing key live";
pub(super) const OTHER_VAULT_KEY: &str = "this owner signing key is another vault's";

/// This install's owner signing key as a checkpoint root signer: the root is
/// the key's own Ed25519 public half, and it signs nothing but a checkpoint
/// statement. Its `Debug` prints only the public half.
pub struct OwnerRootSigner {
    signing: SigningKey,
    /// Where the seed was read from, for a key read from a keystore slot;
    /// `None` for a key opened from under the device PIN for one use.
    slot_home: Option<SlotHome>,
}

/// The keystore slot a key's seed was read from.
struct SlotHome {
    keystore: Arc<dyn DeviceKeystore>,
    slot: KeystoreSlot,
}

impl std::fmt::Debug for OwnerRootSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnerRootSigner")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}

impl OwnerRootSigner {
    /// The key `seed` names, derived straight into guarded memory.
    pub(super) fn from_seed(seed: &[u8; 32]) -> Self {
        let derived = super::derive_guarded(OWNER_SIGNING_CONTEXT, &[&seed[..]]);
        Self {
            signing: SigningKey::from_bytes(&derived),
            slot_home: None,
        }
    }

    /// The key the seed of `slot` names, read from `keystore`. It signs only
    /// on that slot's vault, only while `keystore` has no device PIN and
    /// never forgot one, and only while `slot` still holds that seed.
    fn from_slot(seed: &[u8; 32], keystore: &Arc<dyn DeviceKeystore>, slot: &KeystoreSlot) -> Self {
        let mut signer = Self::from_seed(seed);
        signer.slot_home = Some(SlotHome {
            keystore: Arc::clone(keystore),
            slot: *slot,
        });
        signer
    }

    /// The key's Ed25519 public half: what the roster names.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// The enrollment's proof of possession: the key's signature over the
    /// challenge the engine made for it.
    pub(super) fn sign_possession(&self, challenge: &[u8]) -> Vec<u8> {
        self.signing.sign(challenge).to_bytes().to_vec()
    }

    /// The key's raw signature over `statement`, for a caller that has
    /// checked the key signs now. Refused for any statement outside the
    /// checkpoint domains.
    pub(super) fn sign_statement(&self, statement: &[u8]) -> Result<Vec<u8>> {
        if !checkpoint_statement_domain(statement) {
            return Err(invalid_authority());
        }
        Ok(self.signing.sign(statement).to_bytes().to_vec())
    }

    /// Why the key does not sign on `vault` now; `None` when it does. A key
    /// read from a slot signs on that slot's vault alone, and stops once a
    /// device PIN is set on its keystore: from then on the key signs from
    /// under the PIN, and what was read before is dead. It stays dead when
    /// that PIN is forgotten: the key was lost with it. The slot is read
    /// too, so the key signs only while its slot holds its seed: when a
    /// writer of the keystore's files removes what says a PIN is set or was
    /// forgotten, a key whose slot is empty or holds another seed stays
    /// dead. A copy of the slot's stored form from before the PIN, put back,
    /// revives it: the module's known limit. A keystore that does not answer
    /// signs nothing. Every key stops when the roster no longer lists it
    /// live.
    fn refusal(&self, vault: &Vault) -> Option<Error> {
        if let Some(home) = &self.slot_home {
            if home.slot.vault_id != *vault.vault_id().as_bytes() {
                return Some(authority_refused(OTHER_VAULT_KEY));
            }
            match slot_seed_bar(home.keystore.as_ref()) {
                Ok(None) => {}
                Ok(Some(SlotSeedBar::PinSet)) => {
                    return Some(pin_refused(DevicePinRefusal::Required));
                }
                Ok(Some(SlotSeedBar::PinForgotten)) => {
                    return Some(super::refused(LOST_WITH_FORGOTTEN_PIN));
                }
                Err(error) => return Some(super::keystore_error(error)),
            }
            match home.keystore.get(&home.slot) {
                Ok(Some(seed)) if Self::from_seed(&seed).public_key() == self.public_key() => {}
                Ok(_) => return Some(super::refused(SEED_LEFT_ITS_SLOT)),
                Err(error) => return Some(super::keystore_error(error)),
            }
        }
        if !vault.owner_key_on_live_roster(&self.public_key()) {
            return Some(authority_refused(KEY_NOT_LIVE));
        }
        None
    }
}

impl CheckpointRootSigner for OwnerRootSigner {
    fn root(&self) -> AuthorityKey {
        AuthorityKey::Ed25519(self.public_key())
    }

    /// Refused for any statement outside the checkpoint domains, for a key
    /// the roster no longer lists live, and for a key read from its slot
    /// once a device PIN is set on its keystore, one was forgotten there, or
    /// the slot no longer holds its seed. Each is checked at this call, so a
    /// signer taken earlier stops with its key.
    fn sign_checkpoint_statement(&self, vault: &Vault, statement: &[u8]) -> Result<Vec<u8>> {
        match self.refusal(vault) {
            Some(refusal) => Err(refusal),
            None => self.sign_statement(statement),
        }
    }

    fn signs_now(&self, vault: &Vault) -> bool {
        self.refusal(vault).is_none()
    }
}

impl Vault {
    /// This install's owner signing key for this vault, from its
    /// [`SlotKind::OwnerSigning`] keystore slot: the seed is made there from
    /// the OS CSPRNG on first use, and a concurrent first use keeps the
    /// slot's first seed. It is no owner root until the owner enrols it
    /// ([`Vault::enrol_device_owner_signing_key`]).
    ///
    /// # Errors
    /// `KeystoreUnavailable` while the host installed no keystore; the
    /// keystore's own refusal. Refused on a device with a PIN set: there the
    /// key rests under the PIN and is never handed out.
    /// [`DevicePinRefusal::NotSet`] on a device whose PIN was forgotten and
    /// that has none now: its next key is made under a new PIN.
    pub fn device_owner_signing_key(&self) -> Result<OwnerRootSigner> {
        let keystore = self.device_keystore()?;
        let machine = self.prepare_install_signing()?;
        let slot = self.owner_signing_slot(machine);
        // One step with a first PIN's set, so that never finds a seed made
        // beside it.
        let pin = self.device_pin();
        let _step = pin.as_deref().map(DevicePin::step);
        slot_owner_signer(&keystore, &slot)
    }

    /// The owner enrols this install's own owner signing key, made in its
    /// keystore slot on first use (FIX 4921): the key signs its challenge
    /// for this install's machine, and the owner's act puts it on the roster,
    /// carried by this install, with `issuer`'s root as its predecessor
    /// ([`Vault::enrol_owner_signing_key_as_host`]). This handle then holds
    /// it as a checkpoint root signer. A key already enrolled and live
    /// answers its enrollment's receipt and is held; one the roster revoked
    /// gives its slot to a fresh key, which is enrolled.
    ///
    /// On a device with a PIN set the key is made and kept under the PIN, so
    /// the enrollment needs the window a right PIN opened. Where the host
    /// installed a device PIN, an enrollment is one step with a PIN's set,
    /// change and forget, and with every other enrollment under that PIN.
    ///
    /// # Errors
    /// `KeystoreUnavailable` while the host installed no keystore; the
    /// enrollment's own refusals. On a device with a PIN set,
    /// [`crate::error::SecretError::DevicePin`]: `Required` outside a window,
    /// and `Unavailable` where the host installed no device PIN on this
    /// handle. `NotSet` on a device whose PIN was forgotten and that has
    /// none now: the owner sets a new PIN first.
    pub fn enrol_device_owner_signing_key(
        &self,
        authority: &ActAuthority,
        issuer: &HostSlipIssuer,
    ) -> Result<OwnerKeyEnrollmentReceipt> {
        let keystore = self.device_keystore()?;
        let machine = self.prepare_install_signing()?;
        let slot = self.owner_signing_slot(machine);
        let pin = self.device_pin();
        let step = pin.as_deref().map(DevicePin::step);
        if device_pin_is_set(keystore.as_ref()).map_err(super::keystore_error)? {
            return match (pin.as_ref(), step) {
                (Some(pin), Some(step)) => self.enrol_pin_bound_owner_signing_key(
                    &step, pin, authority, issuer, machine, slot,
                ),
                _ => Err(no_device_pin_here()),
            };
        }
        self.enrol_slot_owner_signing_key(authority, issuer, machine, &keystore, slot)
    }

    /// [`Vault::enrol_device_owner_signing_key`] on a device with no PIN
    /// set: the key rests in its slot.
    fn enrol_slot_owner_signing_key(
        &self,
        authority: &ActAuthority,
        issuer: &HostSlipIssuer,
        machine: EntityId,
        keystore: &Arc<dyn DeviceKeystore>,
        slot: KeystoreSlot,
    ) -> Result<OwnerKeyEnrollmentReceipt> {
        let mut signer = slot_owner_signer(keystore, &slot)?;
        // The owner's proof is revalidated before the roster is read.
        let mut challenge =
            self.owner_key_enrollment_challenge_as(authority, machine, &signer.public_key())?;
        match self.listed_owner_key(&signer.public_key())? {
            Some(listed) if listed.live => {
                self.hold_checkpoint_root_signer(Arc::new(signer));
                return Ok(OwnerKeyEnrollmentReceipt {
                    entry: listed.entry,
                    machine: listed.machine,
                    public_key: listed.public_key,
                });
            }
            // A revoked key is never enrolled again: a fresh seed takes its slot.
            Some(_) => {
                DeviceKeystore::delete(keystore.as_ref(), &slot).map_err(super::keystore_error)?;
                signer = slot_owner_signer(keystore, &slot)?;
                challenge = self.owner_key_enrollment_challenge_as(
                    authority,
                    machine,
                    &signer.public_key(),
                )?;
            }
            None => {}
        }
        let input = OwnerKeyEnrollment {
            machine,
            public_key: signer.public_key(),
            proof: signer.sign_possession(&challenge),
        };
        let receipt = self.enrol_owner_signing_key_as_host(authority, input, issuer)?;
        self.hold_checkpoint_root_signer(Arc::new(signer));
        Ok(receipt)
    }

    /// Holds this install's owner signing key as a checkpoint root signer
    /// when the roster names it live: the call where the vault opens with
    /// its keystore, after this install's signing keys loaded. It never
    /// makes a seed. A failure is logged by kind, never with key material.
    /// True when it is held.
    ///
    /// On a device with no PIN set the key is read from its slot. On a
    /// device with a PIN set the slot is never read as a key: inside a
    /// window the key is opened from under the PIN and held without its
    /// seed, and a seed that still rests in the slot goes under the PIN
    /// first ([`Vault::confirm_device_pin`]); outside a window nothing new
    /// is held. A host that installed no device PIN holds no key there, and
    /// that is logged. On a device whose PIN was forgotten and that has none
    /// now, a seed left in the slot is no key, and nothing is held.
    pub fn hold_device_owner_signer_logged(&self) -> bool {
        held_logged(self.hold_device_owner_signer())
    }

    fn hold_device_owner_signer(&self) -> Result<bool> {
        let keystore = self.device_keystore()?;
        let machine = self.prepare_install_signing()?;
        let slot = self.owner_signing_slot(machine);
        let pin = self.device_pin();
        let step = pin.as_deref().map(DevicePin::step);
        match slot_seed_bar(keystore.as_ref()).map_err(super::keystore_error)? {
            Some(SlotSeedBar::PinSet) => match (pin.as_ref(), step) {
                (Some(pin), Some(step)) => {
                    self.hold_pin_bound_owner_signer(&step, pin, keystore.as_ref(), &slot)
                }
                _ => Err(no_device_pin_here()),
            },
            // What a forgotten PIN left in the slot is no key.
            Some(SlotSeedBar::PinForgotten) => Ok(false),
            None => match keystore.get(&slot).map_err(super::keystore_error)? {
                Some(seed) => self.hold_owner_signer_if_enrolled(OwnerRootSigner::from_slot(
                    &seed, &keystore, &slot,
                )),
                None => Ok(false),
            },
        }
    }

    /// Holds `signer` when the roster names its key live as an enrolled
    /// owner key; true when it is held.
    fn hold_owner_signer_if_enrolled(&self, signer: OwnerRootSigner) -> Result<bool> {
        let live = self
            .listed_owner_key(&signer.public_key())?
            .is_some_and(|listed| listed.live);
        if live {
            self.hold_checkpoint_root_signer(Arc::new(signer));
        }
        Ok(live)
    }

    /// Whether the roster lists `public_key` as a live key now: the rule a
    /// held owner signing key signs under at each use. A roster that cannot
    /// be read lists nothing.
    pub(super) fn owner_key_on_live_roster(&self, public_key: &[u8; 32]) -> bool {
        let key = AuthorityKey::Ed25519(*public_key);
        let live = self
            .store
            .env
            .read_txn()
            .map_err(Error::from)
            .and_then(|txn| {
                let fold = self.authority_view_readonly_in_txn(&txn)?;
                Ok(fold.roster.get(&key).is_some_and(|device| !device.revoked))
            });
        live.unwrap_or(false)
    }

    /// The enrolled owner key `public_key` names, a revoked one included;
    /// `None` before its enrollment.
    pub(super) fn listed_owner_key(
        &self,
        public_key: &[u8; 32],
    ) -> Result<Option<EnrolledOwnerKey>> {
        Ok(self
            .enrolled_owner_keys()?
            .into_iter()
            .find(|listed| listed.public_key == *public_key))
    }

    pub(super) fn owner_signing_slot(&self, machine: EntityId) -> KeystoreSlot {
        KeystoreSlot {
            vault_id: *self.vault_id().as_bytes(),
            install: *machine.as_bytes(),
            kind: SlotKind::OwnerSigning,
        }
    }
}

/// This install's owner signing key from `slot`, its seed made there on
/// first use: only on a device that has no PIN and never forgot one. The
/// rule is asked again once the seed rests. A PIN that a process sharing no
/// device PIN with this one set meanwhile leaves that seed in the slot,
/// where it signs nothing.
fn slot_owner_signer(
    keystore: &Arc<dyn DeviceKeystore>,
    slot: &KeystoreSlot,
) -> Result<OwnerRootSigner> {
    let slot_keys_allowed = || -> Result<()> {
        match slot_seed_bar(keystore.as_ref()).map_err(super::keystore_error)? {
            None => Ok(()),
            Some(SlotSeedBar::PinSet) => Err(super::refused(KEPT_UNDER_DEVICE_PIN)),
            Some(SlotSeedBar::PinForgotten) => Err(pin_refused(DevicePinRefusal::NotSet)),
        }
    };
    slot_keys_allowed()?;
    let seed = super::slot_seed(keystore.as_ref(), slot)?;
    slot_keys_allowed()?;
    Ok(OwnerRootSigner::from_slot(&seed, keystore, slot))
}

/// `held`, a failure logged by kind and answered as not held.
pub(super) fn held_logged(held: Result<bool>) -> bool {
    held.unwrap_or_else(|error| {
        tracing::warn!(
            kind = ?error.kind(),
            "this install's owner signing key was not held; it signs no checkpoint here"
        );
        false
    })
}
