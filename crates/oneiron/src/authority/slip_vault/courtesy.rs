//! The host's signature on a courtesy deletion ask and on its answer
//! (OF-273). A peer accepts either only where it pinned this host's key.
//! The same key signs a shared vault's outcome notices for a removed device
//! (FIX 2053), which accepts them only under the home root it trusts. After a
//! re-root the live root signs again a queued ask or answer a root it
//! succeeded signed, body untouched (FIX 5088).

use ed25519_dalek::Signer;

use super::HostSlipIssuer;
use crate::authority::{
    AuthorityFold, AuthoritySignature, AuthorityVaultId, invalid_authority,
    verify_authority_signature,
};
use crate::deletion::{
    COOP_DELETION_REPLY_DOMAIN, COOP_DELETION_REQUEST_DOMAIN, CooperativeDeletionReply,
    CooperativeDeletionReplyOutcome, CooperativeDeletionRequest, SignedCooperativeDeletionReply,
    SignedCooperativeDeletionRequest, encode_cooperative_deletion_reply_body,
    encode_cooperative_deletion_request_body,
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

    /// Signs again, while this host's key is `fold`'s live root, an ask a
    /// root it succeeded signed and the owner queued (FIX 5088): `body` is
    /// that ask's canonical body exactly, its clock, worlds, cutoff, ids and
    /// nonce kept, never a fresh ask's. Only the signature changes.
    pub(crate) fn resign_cooperative_deletion_request(
        &self,
        fold: &AuthorityFold,
        body: &CooperativeDeletionRequest,
    ) -> Result<SignedCooperativeDeletionRequest> {
        super::require_host(fold, self)?;
        let bytes = encode_cooperative_deletion_request_body(body)?;
        Ok(SignedCooperativeDeletionRequest {
            body: body.clone(),
            signature: self.courtesy_signature(&[COOP_DELETION_REQUEST_DOMAIN, &bytes].concat())?,
        })
    }

    /// [`Self::resign_cooperative_deletion_request`] for a queued answer:
    /// its outcome, ids, nonce and clock kept.
    pub(crate) fn resign_cooperative_deletion_reply(
        &self,
        fold: &AuthorityFold,
        body: &CooperativeDeletionReply,
    ) -> Result<SignedCooperativeDeletionReply> {
        super::require_host(fold, self)?;
        let bytes = encode_cooperative_deletion_reply_body(body)?;
        Ok(SignedCooperativeDeletionReply {
            body: body.clone(),
            signature: self.courtesy_signature(&[COOP_DELETION_REPLY_DOMAIN, &bytes].concat())?,
        })
    }

    /// This host key's signature over `transcript`, checked.
    fn courtesy_signature(&self, transcript: &[u8]) -> Result<AuthoritySignature> {
        let public_key = self.public_key();
        let signature = AuthoritySignature {
            suite: public_key.suite(),
            public_key,
            signature: self.signing.sign(transcript).to_bytes().to_vec(),
        };
        if !verify_authority_signature(&signature, transcript) {
            return Err(invalid_authority());
        }
        Ok(signature)
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
