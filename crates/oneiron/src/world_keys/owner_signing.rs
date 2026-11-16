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

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron_keystore::{DeviceKeystore, KeystoreSlot, SlotKind};

use crate::authority::{
    ACTOR_CLASS_HUMAN, ActAuthority, AuthorityEntryHash, AuthorityKey, AuthorityLogEntry,
    AuthorityOp, AuthorityVaultId, CheckpointRootSigner, EnrolledOwnerKey, HostSlipIssuer,
    OwnerKeyEnrollment, OwnerKeyEnrollmentReceipt, RecoveryRootId, authority_transcript,
    checkpoint_statement_domain, invalid_authority, root_appointment_challenge,
};
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::vault::Vault;

/// The context the signing key is derived under from its seed.
const OWNER_SIGNING_CONTEXT: &str = "oneiron/owner-signing-key/v1";

/// Why a managed host's serving install enrols no owner signing key of its
/// own ([`Vault::enrol_serving_install_owner_signing_key`]).
const MANAGED_HOST_HOLDS_NO_OWNER_KEY: &str =
    "a managed host holds no owner key: enrol one on your own device";

/// This install's owner signing key as a checkpoint root signer: the root is
/// the key's own Ed25519 public half, and it signs nothing but a checkpoint
/// statement and, as the owner's proof, the transcript of an owner act this
/// install carries (row CARRIER-OWNER-PROOF). Its `Debug` prints only the
/// public half.
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
    fn from_seed(seed: &[u8; 32]) -> Self {
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
    fn sign_possession(&self, challenge: &[u8]) -> Vec<u8> {
        self.signing.sign(challenge).to_bytes().to_vec()
    }

    /// A root appointment's proof of possession for this key as its
    /// successor (OWNER-ANCHOR-ROOT-RECOVERY): its signature over
    /// [`root_appointment_challenge`] for `vault_id`, `root` and `parents`.
    pub(crate) fn sign_appointment_challenge(
        &self,
        vault_id: &AuthorityVaultId,
        root: &RecoveryRootId,
        parents: &[AuthorityEntryHash],
    ) -> Result<Vec<u8>> {
        let challenge = root_appointment_challenge(vault_id, root, parents, &self.public_key())?;
        Ok(self.sign_possession(&challenge))
    }

    /// This key's signature, as an appointed successor root, over the
    /// authority transcript of `entry`: its own binding of an owner as
    /// `human`, which it signs right after its appointment. Refused for any
    /// other row.
    pub(crate) fn sign_successor_binding(&self, entry: &AuthorityLogEntry) -> Result<Vec<u8>> {
        let own = self.root();
        let binds_self = matches!(&entry.op, AuthorityOp::BindActor {
            authority_key,
            actor_class,
            ..
        } if *authority_key == own && actor_class == ACTOR_CLASS_HUMAN);
        if !binds_self || entry.signer.public_key != own || !entry.cosigns.is_empty() {
            return Err(invalid_authority());
        }
        Ok(self
            .signing
            .sign(&authority_transcript(entry)?)
            .to_bytes()
            .to_vec())
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

    /// Refused for any bytes outside the authority transcript domain.
    fn sign_owner_proof(&self, transcript: &[u8]) -> Result<Vec<u8>> {
        if !transcript.starts_with(crate::authority::AUTHORITY_TRANSCRIPT_DOMAIN) {
            return Err(invalid_authority());
        }
        Ok(self.signing.sign(transcript).to_bytes().to_vec())
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
    /// keystore's own refusal.
    pub fn device_owner_signing_key(&self) -> Result<OwnerRootSigner> {
        let keystore = self.device_keystore()?;
        let machine = self.prepare_install_signing()?;
        let seed = super::slot_seed(keystore.as_ref(), &self.owner_signing_slot(machine))?;
        Ok(OwnerRootSigner::from_seed(&seed))
    }

    /// This install's [`SlotKind::OwnerSigning`] slot and the keystore that
    /// holds it, made ready outside any writer, since preparing this
    /// install's signing keys writes.
    ///
    /// # Errors
    /// `KeystoreUnavailable` while the host installed no keystore; the
    /// install signing keys' own refusals.
    pub(crate) fn device_owner_signing_slot(&self) -> Result<OwnerSigningSlot> {
        let keystore = self.device_keystore()?;
        let machine = self.prepare_install_signing()?;
        Ok(OwnerSigningSlot {
            keystore,
            slot: self.owner_signing_slot(machine),
        })
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
    /// # Errors
    /// `KeystoreUnavailable` while the host installed no keystore; the
    /// enrollment's own refusals.
    pub fn enrol_device_owner_signing_key(
        &self,
        authority: &ActAuthority,
        issuer: &HostSlipIssuer,
    ) -> Result<OwnerKeyEnrollmentReceipt> {
        let keystore = self.device_keystore()?;
        let machine = self.prepare_install_signing()?;
        let slot = self.owner_signing_slot(machine);
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

    /// The owner enrols the owner signing key of the install that serves
    /// this vault: a server's own `enroll-this-install`
    /// ([`Vault::enrol_device_owner_signing_key`] for the serving install).
    ///
    /// An enrolled owner key proves the owner acts its install carries (row
    /// CARRIER-OWNER-PROOF), so it belongs on a machine the owner holds. A
    /// managed host's server is not one: on a `Hosted` vault this refuses
    /// before it makes a key or writes a row (ruling
    /// CARRIER-HOSTED-SERVER-OWNER-KEY = A). A device's own install of a
    /// hosted vault still enrols its key through
    /// [`Vault::enrol_device_owner_signing_key`].
    ///
    /// # Errors
    /// [`RecordError::AuthorityRefused`] on a `Hosted` vault; otherwise as
    /// [`Vault::enrol_device_owner_signing_key`].
    pub fn enrol_serving_install_owner_signing_key(
        &self,
        authority: &ActAuthority,
        issuer: &HostSlipIssuer,
    ) -> Result<OwnerKeyEnrollmentReceipt> {
        if self.privacy_posture() == crate::HostingPrivacyPosture::Hosted {
            return Err(Error::Record(RecordError::AuthorityRefused(
                MANAGED_HOST_HOLDS_NO_OWNER_KEY,
            )));
        }
        self.enrol_device_owner_signing_key(authority, issuer)
    }

    /// Holds this install's owner signing key as a checkpoint root signer
    /// when its slot holds one and the roster names it live: the call where
    /// the vault opens with its keystore, after this install's signing keys
    /// loaded. It never makes a seed. A failure is logged by kind, never with
    /// key material. True when it is held.
    pub fn hold_device_owner_signer_logged(&self) -> bool {
        let held = self.device_keystore().and_then(|keystore| {
            let machine = self.prepare_install_signing()?;
            match keystore
                .get(&self.owner_signing_slot(machine))
                .map_err(super::keystore_error)?
            {
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

    /// The enrolled owner key `public_key` names, a revoked one included;
    /// `None` before its enrollment.
    fn listed_owner_key(&self, public_key: &[u8; 32]) -> Result<Option<EnrolledOwnerKey>> {
        Ok(self
            .enrolled_owner_keys()?
            .into_iter()
            .find(|listed| listed.public_key == *public_key))
    }

    fn owner_signing_slot(&self, machine: EntityId) -> KeystoreSlot {
        KeystoreSlot {
            vault_id: *self.vault_id().as_bytes(),
            install: *machine.as_bytes(),
            kind: SlotKind::OwnerSigning,
        }
    }
}

/// An install's owner signing slot ([`Vault::device_owner_signing_slot`]).
pub(crate) struct OwnerSigningSlot {
    keystore: Arc<dyn DeviceKeystore>,
    slot: KeystoreSlot,
}

impl OwnerSigningSlot {
    /// A new owner signing key, made in this slot from the OS CSPRNG after
    /// the slot's seed is dropped: a root appointment's successor
    /// (OWNER-ANCHOR-ROOT-RECOVERY), which must be a key no row names. Never
    /// the slot's existing key, which the roster may name, live or revoked.
    /// It touches the keystore alone, so the appointment's writer makes it
    /// once the roster reads rootless there: a door run checked before
    /// another run's appointment committed is refused first, and never drops
    /// the seed of that run's successor, a live root key.
    ///
    /// # Errors
    /// The keystore's own refusal.
    pub(crate) fn fresh_key(&self) -> Result<OwnerRootSigner> {
        DeviceKeystore::delete(self.keystore.as_ref(), &self.slot)
            .map_err(super::keystore_error)?;
        Ok(OwnerRootSigner::from_seed(&*super::slot_seed(
            self.keystore.as_ref(),
            &self.slot,
        )?))
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
