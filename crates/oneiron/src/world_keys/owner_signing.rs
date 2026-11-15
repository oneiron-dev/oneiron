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
//! PIN opened. Either way, a held key signs only while the roster lists it
//! live ([`CheckpointRootSigner::signs_now`]).

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron_keystore::{DeviceKeystore, KeystoreSlot, SlotKind};

use crate::authority::{
    ActAuthority, AuthorityKey, CheckpointRootSigner, EnrolledOwnerKey, HostSlipIssuer,
    OwnerKeyEnrollment, OwnerKeyEnrollmentReceipt, checkpoint_statement_domain, invalid_authority,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::vault::Vault;

/// The context the signing key is derived under from its seed.
const OWNER_SIGNING_CONTEXT: &str = "oneiron/owner-signing-key/v1";

const KEPT_UNDER_DEVICE_PIN: &str = "this install's owner signing key is kept under the device \
                                     PIN and is not handed out";

/// This install's owner signing key as a checkpoint root signer: the root is
/// the key's own Ed25519 public half, and it signs nothing but a checkpoint
/// statement. Its `Debug` prints only the public half.
pub struct OwnerRootSigner {
    signing: SigningKey,
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
        }
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
}

impl CheckpointRootSigner for OwnerRootSigner {
    fn root(&self) -> AuthorityKey {
        AuthorityKey::Ed25519(self.public_key())
    }

    /// Refused for any statement outside the checkpoint domains.
    fn sign_checkpoint_statement(&self, statement: &[u8]) -> Result<Vec<u8>> {
        if !checkpoint_statement_domain(statement) {
            return Err(invalid_authority());
        }
        Ok(self.signing.sign(statement).to_bytes().to_vec())
    }

    /// Only while the roster lists the key live: a key revoked after it was
    /// held stops at its next use.
    fn signs_now(&self, vault: &Vault) -> bool {
        vault.owner_key_on_live_roster(&self.public_key())
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
    pub fn device_owner_signing_key(&self) -> Result<OwnerRootSigner> {
        let keystore = self.device_keystore()?;
        let machine = self.prepare_install_signing()?;
        if self.owner_key_device_pin(keystore.as_ref())?.is_some() {
            return Err(super::refused(KEPT_UNDER_DEVICE_PIN));
        }
        let seed = super::slot_seed(keystore.as_ref(), &self.owner_signing_slot(machine))?;
        Ok(OwnerRootSigner::from_seed(&seed))
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
    /// the enrollment needs the window a right PIN opened.
    ///
    /// # Errors
    /// `KeystoreUnavailable` while the host installed no keystore; the
    /// enrollment's own refusals. On a device with a PIN set,
    /// [`crate::error::SecretError::DevicePin`]: `Required` outside a window,
    /// and `Unavailable` where the host installed no device PIN on this
    /// handle.
    pub fn enrol_device_owner_signing_key(
        &self,
        authority: &ActAuthority,
        issuer: &HostSlipIssuer,
    ) -> Result<OwnerKeyEnrollmentReceipt> {
        let keystore = self.device_keystore()?;
        let machine = self.prepare_install_signing()?;
        let slot = self.owner_signing_slot(machine);
        if let Some(pin) = self.owner_key_device_pin(keystore.as_ref())? {
            return self.enrol_pin_bound_owner_signing_key(pin, authority, issuer, machine, slot);
        }
        let mut signer = OwnerRootSigner::from_seed(&*super::slot_seed(keystore.as_ref(), &slot)?);
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
                signer = OwnerRootSigner::from_seed(&*super::slot_seed(keystore.as_ref(), &slot)?);
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
    /// when its slot holds one and the roster names it live: the call where
    /// the vault opens with its keystore, after this install's signing keys
    /// loaded. It never makes a seed. A failure is logged by kind, never with
    /// key material. True when it is held. A key that rests under the device
    /// PIN is held without its seed, and one that still rests in its slot
    /// goes under the PIN first when a window is open
    /// ([`Vault::confirm_device_pin`]).
    pub fn hold_device_owner_signer_logged(&self) -> bool {
        let held = self.device_keystore().and_then(|keystore| {
            let machine = self.prepare_install_signing()?;
            let slot = self.owner_signing_slot(machine);
            if let Some(held) = self.hold_pin_bound_owner_signer(keystore.as_ref(), &slot)? {
                return Ok(held);
            }
            match keystore.get(&slot).map_err(super::keystore_error)? {
                Some(seed) => self.hold_owner_signer_if_enrolled(OwnerRootSigner::from_seed(&seed)),
                None => Ok(false),
            }
        });
        held_logged(held)
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

/// `held`, a failure logged by kind and answered as not held.
fn held_logged(held: Result<bool>) -> bool {
    held.unwrap_or_else(|error| {
        tracing::warn!(
            kind = ?error.kind(),
            "this install's owner signing key was not held; it signs no checkpoint here"
        );
        false
    })
}
