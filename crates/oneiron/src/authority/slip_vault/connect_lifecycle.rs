//! Owner-bound doors over the existing federation lifecycle fold.
use ed25519_dalek::Signer;
use rand_core::{OsRng, RngCore};

use super::connect::{local_vault_id, offer_for};
use super::{HostSlipIssuer, require_host};
use crate::Vault;
use crate::authority::{
    AuthorityFold, AuthorityOp, ConnectOffer, FederationLifecycleAction, FederationLifecycleKind,
    FederationPactState, federation_scope_digest, invalid_authority,
};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::federation::{Ceiling, FederationDirectionScope, FederationPactScope, encode_federation_pact_scope};

/// A host's signed half of a reciprocal re-scope at one fresh consent epoch.
#[derive(Debug, Clone)]
pub struct ConnectRescopeOffer {
    pub epoch: u64,
    pub offer: ConnectOffer,
}

fn pact(fold: &AuthorityFold, id: &[u8; 32]) -> Result<FederationPactState> {
    fold.federation_pacts.get(id).cloned().ok_or(Error::EntityNotFound)
}

fn action(
    state: &FederationPactState,
    pact_id: [u8; 32],
    kind: FederationLifecycleKind,
    epoch: u64,
) -> FederationLifecycleAction {
    FederationLifecycleAction {
        kind,
        pact_id,
        grant_ref: state.grant_ref,
        peer_vault_id: state.peer_vault_id,
        pact_epoch: epoch,
        pact_scope: None,
        effective_scope: None,
        scope_digest: None,
        gesture: None,
        successor_vault_id: None,
        pact_nonce: nonce(),
    }
}

fn rescope_action(
    state: &FederationPactState,
    offered: &ConnectRescopeOffer,
) -> Result<FederationLifecycleAction> {
    let mut action = action(state, offered.offer.pact_id, FederationLifecycleKind::Rescope, offered.epoch);
    action.pact_nonce = offered.offer.pact_nonce;
    action.scope_digest = Some(federation_scope_digest(
        &action.pact_nonce,
        &encode_federation_pact_scope(&offered.offer.pact_scope)?,
    ));
    action.pact_scope = Some(offered.offer.pact_scope.clone());
    Ok(action)
}

impl Vault {
    /// Signs a fresh disclosed reciprocal re-scope. No authority changes until accept.
    pub fn propose_connect_rescope_as(
        &self,
        owner: &AuthenticatedOwner,
        issuer: &HostSlipIssuer,
        pact_id: [u8; 32],
        epoch: u64,
        scope: FederationPactScope,
    ) -> Result<ConnectRescopeOffer> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let local = local_vault_id(&fold, issuer)?;
        let state = pact(&fold, &pact_id)?;
        if state.status.is_terminal() || state.pact_epoch.checked_add(1) != Some(epoch) {
            return Err(invalid_authority());
        }
        self.require_connect_rescope_grant_in_txn(&txn, &state, &local, &scope)?;
        let mut action = action(&state, pact_id, FederationLifecycleKind::Rescope, epoch);
        action.scope_digest = Some(federation_scope_digest(
            &action.pact_nonce,
            &encode_federation_pact_scope(&scope)?,
        ));
        action.pact_scope = Some(scope);
        Ok(ConnectRescopeOffer { epoch, offer: offer_for(issuer, &action, local)? })
    }

    /// Accepts the peer host's matching half through the authority fold, not a local substitute.
    pub fn accept_connect_rescope_as(
        &self,
        owner: &AuthenticatedOwner,
        issuer: &HostSlipIssuer,
        offered: &ConnectRescopeOffer,
    ) -> Result<(FederationPactState, ConnectRescopeOffer)> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let fold = self.authority_view_readonly_in_txn(txn)?;
            let local = local_vault_id(&fold, issuer)?;
            let state = pact(&fold, &offered.offer.pact_id)?;
            if offered.offer.to_vault != local || offered.offer.from_vault != state.peer_vault_id {
                return Err(invalid_authority());
            }
            self.require_connect_rescope_grant_in_txn(txn, &state, &local, &offered.offer.pact_scope)?;
            let mut action = rescope_action(&state, offered)?;
            action.gesture = Some(offered.offer.gesture.clone());
            let counter = ConnectRescopeOffer { epoch: offered.epoch, offer: offer_for(issuer, &action, local)? };
            // Exact retries still verify the peer's gesture. An arbitrary signature
            // cannot turn a cached state into a successful owner commitment.
            if !state.status.is_terminal()
                && state.pact_epoch == offered.epoch
                && Some(state.scope_digest) == action.scope_digest
                && state.pact_scope == offered.offer.pact_scope
            {
                let signature = crate::authority::AuthoritySignature {
                    suite: offered.offer.gesture.signer.suite(),
                    public_key: offered.offer.gesture.signer.clone(),
                    signature: offered.offer.gesture.signature.clone(),
                };
                let transcript = crate::authority::federation_pact_transcript(
                    action.kind, &action.pact_id, &local, &state.peer_vault_id,
                    action.pact_epoch, &state.scope_digest, None, &action.pact_nonce,
                )?;
                if signature.public_key != state.peer_owner_key
                    || !crate::authority::verify_authority_signature(&signature, &transcript)
                {
                    return Err(invalid_authority());
                }
                return Ok((state, counter));
            }
            self.append_slip_op_in_txn(txn, issuer, AuthorityOp::FederationLifecycle(action))?;
            Ok((pact(&*self.authority_view_readonly_in_txn(txn)?, &offered.offer.pact_id)?, counter))
        })
    }

    /// Narrows the current outbound overlay without ending the relationship.
    pub fn narrow_connect_as(
        &self,
        owner: &AuthenticatedOwner,
        issuer: &HostSlipIssuer,
        pact_id: [u8; 32],
        epoch: u64,
        outbound: FederationDirectionScope,
    ) -> Result<FederationPactState> {
        outbound.validate()?;
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let fold = self.authority_view_readonly_in_txn(txn)?;
            require_host(&fold, issuer)?;
            let state = pact(&fold, &pact_id)?;
            if !Ceiling::new(outbound.clone()).is_within(&Ceiling::new(state.effective_scope.clone())) {
                return Err(invalid_authority());
            }
            let mut action = action(&state, pact_id, FederationLifecycleKind::Rescope, epoch);
            action.effective_scope = Some(outbound);
            self.append_slip_op_in_txn(txn, issuer, AuthorityOp::FederationLifecycle(action))?;
            pact(&*self.authority_view_readonly_in_txn(txn)?, &pact_id)
        })
    }

    /// Unilateral terminal disconnect: both directions cease at this host.
    pub fn disconnect_connect_as(
        &self,
        owner: &AuthenticatedOwner,
        issuer: &HostSlipIssuer,
        pact_id: [u8; 32],
    ) -> Result<FederationPactState> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let fold = self.authority_view_readonly_in_txn(txn)?;
            require_host(&fold, issuer)?;
            let state = pact(&fold, &pact_id)?;
            if state.status == crate::authority::FederationPactStatus::Disconnected {
                return Ok(state);
            }
            let action = action(&state, pact_id, FederationLifecycleKind::Disconnect, state.pact_epoch);
            self.append_slip_op_in_txn(txn, issuer, AuthorityOp::FederationLifecycle(action))?;
            pact(&*self.authority_view_readonly_in_txn(txn)?, &pact_id)
        })
    }
}

fn nonce() -> [u8; 16] {
    let mut nonce = [0; 16];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

impl HostSlipIssuer {
    /// Signs only the typed, pact-bound foreign-world delivery transcript.
    pub fn sign_connect_window(
        &self,
        body: &crate::task_verb::sdk::ConnectWindow,
    ) -> Result<String> {
        Ok(crate::entity_id::bytes_to_hex_lower(&self.signing.sign(&body.transcript()?).to_bytes()))
    }
}
