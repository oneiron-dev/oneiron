//! Core half of `deletion::coop_reply`: its store-layer items live in `oneiron_store::deletion::coop_reply` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::deletion::coop_reply::*;

use super::coop_request::{
    binary, decode, encode, envelope_signature, fields, invalid, signature_value, uint,
};
use crate::Vault;
use crate::error::Result;
use oneiron_authority::authority::{AuthorityKey, AuthoritySignature, verify_authority_signature};
use rmpv::Value;

impl Vault {
    /// Signs this vault's answer to an ask its pact's peer sent.
    pub fn sign_cooperative_deletion_reply<S>(
        &self,
        pact_id: &[u8; 32],
        nonce: [u8; 16],
        outcome: CooperativeDeletionReplyOutcome,
        signer_key: AuthorityKey,
        signer: S,
    ) -> Result<SignedCooperativeDeletionReply>
    where
        S: FnOnce(&[u8]) -> Result<Vec<u8>>,
    {
        let fold = self.authority_fold()?;
        let pact = fold.federation_pacts.get(pact_id).ok_or_else(invalid)?;
        let body = CooperativeDeletionReply {
            pact_id: *pact_id,
            requester_vault_id: pact.peer_vault_id,
            responder_vault_id: fold.vault_id.ok_or_else(invalid)?,
            nonce,
            outcome,
            ts: crate::unix_seconds_now(),
        };
        let bytes = encode_cooperative_deletion_reply_body(&body)?;
        let transcript = [COOP_DELETION_REPLY_DOMAIN, &bytes].concat();
        let signature = AuthoritySignature {
            suite: signer_key.suite(),
            public_key: signer_key,
            signature: signer(&transcript)?,
        };
        if !verify_authority_signature(&signature, &transcript) {
            return Err(invalid());
        }
        Ok(SignedCooperativeDeletionReply { body, signature })
    }
}
