//! Core half of `deletion::coop_request`: its store-layer items live in `oneiron_store::deletion::coop_request` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::deletion::coop_request::*;

use crate::entity_id::LocalWorldId;
use crate::error::{Error, RecordError, Result};
use crate::{EntityId, Vault};
use oneiron_authority::authority::{
    AuthorityKey, AuthoritySignature, AuthoritySignatureSuite, FederationPactStatus,
    verify_authority_signature,
};
use rmpv::Value;

impl Vault {
    /// Signs a one-way courtesy request only after disconnect or dissolution:
    /// the owner's whole selection, as one signed ask per page (FIX 7941),
    /// each under `signer_key` and the same pact claim, with its page and
    /// page count in the signed bytes and one clock for every page. Nothing
    /// refuses a selection for its size.
    pub fn sign_cooperative_deletion_request<S>(
        &self,
        pact_id: &[u8; 32],
        worlds: Vec<EntityId>,
        epoch_cutoff: u64,
        nonce: [u8; 16],
        signer_key: AuthorityKey,
        mut signer: S,
    ) -> Result<Vec<SignedCooperativeDeletionRequest>>
    where
        S: FnMut(&[u8]) -> Result<Vec<u8>>,
    {
        let fold = self.authority_fold()?;
        let pact = fold
            .federation_pacts
            .get(pact_id)
            .filter(|p| {
                matches!(
                    p.status,
                    FederationPactStatus::Disconnected | FederationPactStatus::Dissolved
                )
            })
            .ok_or(RecordError::CooperativeDeletionRequiresTerminalPact)?;
        if epoch_cutoff > pact.terminal_epoch.unwrap_or(pact.pact_epoch) {
            return Err(invalid());
        }
        let requester_vault_id = fold.vault_id.ok_or_else(invalid)?;
        let ts = crate::unix_seconds_now();
        let selection = selection_pages(worlds);
        let pages = u32::try_from(selection.len()).map_err(|_| invalid())?;
        let mut signed = Vec::with_capacity(selection.len());
        for (page, worlds) in (0..pages).zip(selection) {
            let body = CooperativeDeletionRequest {
                pact_id: *pact_id,
                requester_vault_id,
                peer_vault_id: pact.peer_vault_id,
                worlds,
                page,
                pages,
                epoch_cutoff,
                ts,
                nonce: page_nonce(&nonce, page, pages),
            };
            let bytes = encode_cooperative_deletion_request_body(&body)?;
            let transcript = [COOP_DELETION_REQUEST_DOMAIN, &bytes].concat();
            let signature = AuthoritySignature {
                suite: signer_key.suite(),
                public_key: signer_key.clone(),
                signature: signer(&transcript)?,
            };
            if !verify_authority_signature(&signature, &transcript) {
                return Err(invalid());
            }
            signed.push(SignedCooperativeDeletionRequest { body, signature });
        }
        Ok(signed)
    }
}
