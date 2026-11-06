//! A kit root's distinct, vault-bound authority signing key. Constructing it
//! grants no authority; the owner must enrol it before loss through OwnerKeyEnroll.

use ed25519_dalek::{Signer, SigningKey};

use super::{RecoveryRootId, RecoveryRootSeed};
use crate::authority::{
    AUTHORITY_TRANSCRIPT_DOMAIN, AuthorityKey, AuthorityVaultId, OwnerKeyEnrollment,
    invalid_authority, owner_key_enrollment_challenge,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::recovery_kit::RestoredKitSecret;

const RECOVERY_AUTHORITY_CONTEXT: &str = "oneiron/owner-recovery-authority/v1";

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
    /// No root activation, enrollment or keystore write happens here.
    pub fn from_seed(seed: &RecoveryRootSeed, vault_id: &AuthorityVaultId) -> Result<Self> {
        let source_root = seed.public(vault_id)?.id;
        let derived = crate::key_material::derive_guarded(
            RECOVERY_AUTHORITY_CONTEXT,
            &[&seed.bytes[..], &vault_id[..]],
        );
        Ok(Self {
            signing: SigningKey::from_bytes(&derived),
            vault_id: *vault_id,
            source_root,
        })
    }

    /// Rebuilds from the existing RecoveryRoot kit type. Piece authentication and
    /// confirmation retain their existing meaning; this adds no piece-count gate.
    pub fn from_restored_kit(
        secret: RestoredKitSecret,
        vault_id: &AuthorityVaultId,
    ) -> Result<Self> {
        let seed = RecoveryRootSeed::from_restored_kit(secret)?;
        Self::from_seed(&seed, vault_id)
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
    /// vault's generated transcripts; this is not an arbitrary signing surface.
    pub(crate) fn sign_authority_transcript(&self, transcript: &[u8]) -> Result<Vec<u8>> {
        if !transcript.starts_with(AUTHORITY_TRANSCRIPT_DOMAIN) {
            return Err(invalid_authority());
        }
        Ok(self.signing.sign(transcript).to_bytes().to_vec())
    }
}
