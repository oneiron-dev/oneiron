//! The host's signature on a courtesy deletion ask and on its answer
//! (OF-273). A peer accepts either only where it pinned this host's key.
//! The same key signs a shared vault's outcome notices for a removed device
//! (FIX 2053), which accepts them only under the home root it trusts.

use ed25519_dalek::Signer;

use super::HostSlipIssuer;
use crate::authority::{
    AuthoritySignature, AuthorityVaultId, invalid_authority, verify_authority_signature,
};
use crate::deletion::{
    CooperativeDeletionReplyOutcome, SignedCooperativeDeletionReply,
    SignedCooperativeDeletionRequest,
};
use crate::error::Result;
use crate::federation::{SharedActOutcome, SignedSharedActOutcome, shared_act_outcome_transcript};
use crate::{EntityId, Vault};

impl HostSlipIssuer {
    /// Signs a one-way ask about `pact_id` with this host's key.
    pub fn sign_cooperative_deletion_request(
        &self,
        vault: &Vault,
        pact_id: &[u8; 32],
        worlds: Vec<EntityId>,
        epoch_cutoff: u64,
        nonce: [u8; 16],
    ) -> Result<SignedCooperativeDeletionRequest> {
        vault.sign_cooperative_deletion_request(
            pact_id,
            worlds,
            epoch_cutoff,
            nonce,
            self.public_key(),
            |transcript| Ok(self.signing.sign(transcript).to_bytes().to_vec()),
        )
    }

    /// Signs this vault's answer to the ask `nonce` under `pact_id`.
    pub fn sign_cooperative_deletion_reply(
        &self,
        vault: &Vault,
        pact_id: &[u8; 32],
        nonce: [u8; 16],
        outcome: CooperativeDeletionReplyOutcome,
    ) -> Result<SignedCooperativeDeletionReply> {
        vault.sign_cooperative_deletion_reply(
            pact_id,
            nonce,
            outcome,
            self.public_key(),
            |transcript| Ok(self.signing.sign(transcript).to_bytes().to_vec()),
        )
    }

    /// Signs `outcome` as a notice of the vault `authority_vault_id` names,
    /// over [`shared_act_outcome_transcript`].
    pub fn sign_shared_act_outcome(
        &self,
        authority_vault_id: AuthorityVaultId,
        outcome: &SharedActOutcome,
    ) -> Result<SignedSharedActOutcome> {
        let transcript = shared_act_outcome_transcript(&authority_vault_id, outcome)?;
        let public_key = self.public_key();
        let signature = AuthoritySignature {
            suite: public_key.suite(),
            public_key,
            signature: self.signing.sign(&transcript).to_bytes().to_vec(),
        };
        if !verify_authority_signature(&signature, &transcript) {
            return Err(invalid_authority());
        }
        Ok(SignedSharedActOutcome {
            authority_vault_id,
            outcome: outcome.clone(),
            signature,
        })
    }
}
