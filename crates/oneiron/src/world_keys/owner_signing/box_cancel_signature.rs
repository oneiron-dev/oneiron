//! An owner key's signature on a Cancel of the release pending at the
//! recovery box ([`RecoveryBoxCancelProof`]), under the rule every owner
//! act's proof follows.

use super::*;
use crate::authority::RecoveryBoxCancelProof;

impl OwnerRootSigner {
    /// This key's signature over `proof`'s transcript for the vault
    /// `vault_id` ([`RecoveryBoxCancelProof::transcript`]): an owner's Cancel
    /// of the release pending at the recovery box. It builds the transcript
    /// itself, so it signs nothing outside that domain. Refused wherever an
    /// owner act's proof is ([`Self::refusal`], the roster read from `fold`).
    /// The caller hands the ground the proof is signed on, as for every
    /// owner proof ([`CheckpointRootSigner::sign_owner_proof`]); the signer
    /// does not read it.
    pub(crate) fn sign_recovery_box_cancel(
        &self,
        vault: &Vault,
        fold: &AuthorityFold,
        _ground: &OwnerProofGround,
        proof: &RecoveryBoxCancelProof,
        vault_id: &AuthorityVaultId,
    ) -> Result<Vec<u8>> {
        if let Some(refusal) = self.refusal(vault, Some(fold)) {
            return Err(refusal);
        }
        Ok(self
            .signing
            .sign(&proof.transcript(vault_id))
            .to_bytes()
            .to_vec())
    }
}
