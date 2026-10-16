//! The host's signature on a courtesy deletion ask and on its answer
//! (OF-273). A peer accepts either only where it pinned this host's key.

use ed25519_dalek::Signer;

use super::HostSlipIssuer;
use crate::deletion::{
    CooperativeDeletionReplyOutcome, SignedCooperativeDeletionReply,
    SignedCooperativeDeletionRequest,
};
use crate::error::Result;
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
}
