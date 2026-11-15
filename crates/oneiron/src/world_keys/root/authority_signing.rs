//! A kit root's distinct, vault-bound authority signing key. Constructing it
//! grants no authority; the owner must enrol it before loss through OwnerKeyEnroll.

use ed25519_dalek::{Signer, SigningKey};
use zeroize::Zeroizing;

use super::{RecoveryRootId, RecoveryRootSeed};
use crate::authority::{
    AUTHORITY_TRANSCRIPT_DOMAIN, AuthorityKey, AuthorityVaultId, LEAVE_NOTICE_DELEGATION_DOMAIN,
    OwnerKeyEnrollment, invalid_authority, owner_key_enrollment_challenge,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::recovery_kit::RestoredKitSecret;

const RECOVERY_AUTHORITY_CONTEXT: &str = "oneiron/owner-recovery-authority/v1";
const RECOVERY_AUTHORITY_GENERATION_CONTEXT: &str =
    "oneiron/owner-recovery-authority-generation/v1";

/// R's authority seed, handed out once by the kit's activation for the box
/// deposit (pass 27 R4 PR 2, WAYBACK-BOX-AUTHORITY-SEED = A). Holds
/// `Zeroizing<[u8; 32]>`: no `Serialize`, a `Debug` that prints no bytes.
/// `Clone` only because [`crate::world_keys::ActivatedRoot`] derives it.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryAuthoritySeed(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for RecoveryAuthoritySeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryAuthoritySeed(<redacted>)")
    }
}

impl RecoveryAuthoritySeed {
    /// The seed bytes, for OPUS-WAYBACK-BOX's deposit. Public so the server
    /// crate reads it; the server drops it until that lands.
    #[must_use]
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The seed from its guarded bytes, in-crate only. The producer is
    /// [`RecoveryAuthoritySigner::authority_seed`].
    pub(crate) fn from_guarded(seed: Zeroizing<[u8; 32]>) -> Self {
        Self(seed)
    }
}

/// A distinct authority key derived from an owner's recovery seed and the
/// consuming vault's identity. It is neither the world-recovery key nor the owner
/// anchor or checkpoint signer. It gains standing only through explicit counted
/// owner-key enrollment, and the authority fold still decides whether it is live.
/// Secret material is wiped on drop and is never serialized.
pub struct RecoveryAuthoritySigner {
    signing: SigningKey,
    vault_id: AuthorityVaultId,
    source_root: RecoveryRootId,
}

impl std::fmt::Debug for RecoveryAuthoritySigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryAuthoritySigner")
            .field("public_key", &self.public_key())
            .field("vault_id", &self.vault_id)
            .field("source_root", &self.source_root)
            .finish_non_exhaustive()
    }
}

impl RecoveryAuthoritySigner {
    /// Derives the same key before and after loss. `vault_id` must come from the
    /// consuming vault's actual authority identity, not a material request's claim.
    /// No root activation, enrollment or keystore write happens here. Generation 0
    /// is today's bytes exactly; generation `g >= 1` derives under a separate
    /// context, so no generation collides with generation 0.
    pub fn from_seed(
        seed: &RecoveryRootSeed,
        vault_id: &AuthorityVaultId,
        generation: u32,
    ) -> Result<Self> {
        let source_root = seed.public(vault_id)?.id;
        Self::from_released_seed(
            Self::authority_seed(seed, vault_id, generation),
            vault_id,
            source_root,
        )
    }

    /// The key's own 32-byte seed, derived from the root's seed for
    /// `vault_id` at `generation`: what the recovery box keeps
    /// (WAYBACK-BOX-AUTHORITY-SEED = A), never the root's seed. It stays in
    /// guarded memory. Generation 0 is today's bytes exactly (the same context
    /// string and inputs); generation `g >= 1` derives under
    /// [`RECOVERY_AUTHORITY_GENERATION_CONTEXT`] with the generation's
    /// big-endian bytes as a third input, so no generation collides with
    /// generation 0. The kit carries no generation; old kits read as
    /// generation 0 by construction, and the roster tells.
    pub(crate) fn authority_seed(
        seed: &RecoveryRootSeed,
        vault_id: &AuthorityVaultId,
        generation: u32,
    ) -> Zeroizing<[u8; 32]> {
        if generation == 0 {
            return crate::key_material::derive_guarded(
                RECOVERY_AUTHORITY_CONTEXT,
                &[&seed.bytes[..], &vault_id[..]],
            );
        }
        let generation = generation.to_be_bytes();
        crate::key_material::derive_guarded(
            RECOVERY_AUTHORITY_GENERATION_CONTEXT,
            &[&seed.bytes[..], &vault_id[..], &generation[..]],
        )
    }

    /// Rebuilds the key from its own seed as the recovery box releases it.
    /// `source_root` is the public binding the box keeps beside the seed. No
    /// door trusts it, since the roster names no root for the key: the
    /// root's door checks the derived key on the roster
    /// ([`crate::Vault::recover_owner_root`]).
    ///
    /// # Errors
    /// An authority error for an all-zero seed, which no kit derives.
    pub fn from_released_seed(
        seed: Zeroizing<[u8; 32]>,
        vault_id: &AuthorityVaultId,
        source_root: RecoveryRootId,
    ) -> Result<Self> {
        if seed.iter().all(|byte| *byte == 0) {
            return Err(invalid_authority());
        }
        Ok(Self {
            signing: SigningKey::from_bytes(&seed),
            vault_id: *vault_id,
            source_root,
        })
    }

    /// Rebuilds from the existing RecoveryRoot kit type. Piece authentication and
    /// confirmation retain their existing meaning; this adds no piece-count gate.
    /// Generation 0 is today's bytes exactly; see [`Self::authority_seed`].
    pub fn from_restored_kit(
        secret: RestoredKitSecret,
        vault_id: &AuthorityVaultId,
        generation: u32,
    ) -> Result<Self> {
        let seed = RecoveryRootSeed::from_restored_kit(secret)?;
        Self::from_seed(&seed, vault_id, generation)
    }

    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    #[must_use]
    pub fn authority_key(&self) -> AuthorityKey {
        AuthorityKey::Ed25519(self.public_key())
    }

    #[must_use]
    pub fn vault_id(&self) -> &AuthorityVaultId {
        &self.vault_id
    }

    /// The public source-root binding, not a current-pin admission condition.
    #[must_use]
    pub fn source_root(&self) -> &RecoveryRootId {
        &self.source_root
    }

    /// The key's own seed back in guarded memory: what the recovery wait
    /// keeps in a device-keystore slot from the hold until the landing or
    /// the cancel (OPUS-WAYBACK). In-crate only, like the seed's producer.
    pub(crate) fn released_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing.to_bytes())
    }

    /// Pure proof of possession for the existing enrollment door. Its owner act,
    /// predecessor, carrying install and counted writer are still required there.
    /// This value is not an enrollment receipt or a successful material issue.
    pub(crate) fn enrollment(
        &self,
        machine: EntityId,
        owner: EntityId,
    ) -> Result<OwnerKeyEnrollment> {
        let public_key = self.public_key();
        let challenge =
            owner_key_enrollment_challenge(&self.vault_id, machine, &public_key, owner)?;
        Ok(OwnerKeyEnrollment {
            machine,
            public_key,
            proof: self.signing.sign(&challenge).to_bytes().to_vec(),
        })
    }

    /// For the same-vault ReRoot writer's callback. The caller supplies this
    /// vault's generated transcripts; this is not an arbitrary signing surface:
    /// an authority entry's, or the move's leave-notice delegation's (FIX
    /// 7932), and nothing under another domain.
    pub(crate) fn sign_authority_transcript(&self, transcript: &[u8]) -> Result<Vec<u8>> {
        Self::check_transcript_domain(transcript)?;
        Ok(self.signing.sign(transcript).to_bytes().to_vec())
    }

    /// Signs `transcript` with a recovery wait's held slot seed (OPUS-WAYBACK
    /// landing): the same domain rule as [`Self::sign_authority_transcript`],
    /// without the signer's vault and source-root bindings, which the landing
    /// rechecks from its fold (the slot keeps the seed alone).
    pub(crate) fn sign_transcript_with_seed(seed: &[u8; 32], transcript: &[u8]) -> Result<Vec<u8>> {
        Self::check_transcript_domain(transcript)?;
        Ok(SigningKey::from_bytes(seed)
            .sign(transcript)
            .to_bytes()
            .to_vec())
    }

    /// The one domain rule both signing halves enforce: an authority entry's
    /// transcript, or a move's leave-notice delegation (FIX 7932), and
    /// nothing else.
    fn check_transcript_domain(transcript: &[u8]) -> Result<()> {
        if !transcript.starts_with(AUTHORITY_TRANSCRIPT_DOMAIN)
            && !transcript.starts_with(LEAVE_NOTICE_DELEGATION_DOMAIN)
        {
            return Err(invalid_authority());
        }
        Ok(())
    }
}
