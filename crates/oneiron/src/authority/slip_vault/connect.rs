//! Connect, signed by each vault's own host-root key (FIX 323, ARCH-0043
//! #relationship-lifecycle). Each owner's host signs the pact both owners
//! approve, so each side's log pins the other host's root key as the pact's
//! peer owner key: the key that host signs its courtesy asks and answers
//! with (OF-273), so the courtesy doors verify them unchanged.

use ed25519_dalek::Signer;
use rand_core::{OsRng, RngCore};

use super::{HostSlipIssuer, random_slip_id, require_host};
use crate::Vault;
use crate::authority::{
    AuthorityFold, AuthorityOp, AuthorityVaultId, FederationLifecycleAction,
    FederationLifecycleKind, FederationPactGesture, FederationPactState, federation_scope_digest,
    invalid_authority, sign_federation_pact_gesture,
};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::{
    FederationDirectionScope, FederationPactScope, encode_federation_pact_scope,
};
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// One host's signed half of a Connect: the terms both owners approve, and
/// that host's gesture over them. The other vault's owner accepts it with
/// [`Vault::accept_connect_as`]; both hosts sign byte-identical transcripts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectOffer {
    /// The vault whose host signed.
    pub from_vault: AuthorityVaultId,
    /// The vault the offer is for.
    pub to_vault: AuthorityVaultId,
    /// The shared pact id, identical on both logs.
    pub pact_id: [u8; 32],
    /// The pact nonce the scope commitment is keyed under.
    pub pact_nonce: [u8; 16],
    /// The full disclosed scope pair, lo/hi by vault id.
    pub pact_scope: FederationPactScope,
    /// The signing host's gesture over the pact transcript.
    pub gesture: FederationPactGesture,
}

impl HostSlipIssuer {
    /// Signs `action`'s pact transcript with this host's key. At Connect the
    /// peer's log pins this key as the pact's peer owner key, the one its
    /// courtesy doors verify this host's asks and answers under.
    pub fn sign_pact_gesture(
        &self,
        action: &FederationLifecycleAction,
        local_vault_id: &AuthorityVaultId,
    ) -> Result<FederationPactGesture> {
        let scope_digest = action.scope_digest.ok_or_else(invalid_authority)?;
        sign_federation_pact_gesture(
            action.kind,
            &action.pact_id,
            local_vault_id,
            &action.peer_vault_id,
            action.pact_epoch,
            &scope_digest,
            action.successor_vault_id.as_ref(),
            &action.pact_nonce,
            self.public_key(),
            |transcript| Ok(self.signing.sign(transcript).to_bytes().to_vec()),
        )
    }
}

/// The Connect action for `grant_ref` with `peer_vault_id` over these terms:
/// epoch 1 and the scope pair's keyed digest, with no gesture yet.
fn connect_action(
    grant_ref: EntityId,
    peer_vault_id: AuthorityVaultId,
    pact_id: [u8; 32],
    pact_nonce: [u8; 16],
    pact_scope: FederationPactScope,
) -> Result<FederationLifecycleAction> {
    let canonical = encode_federation_pact_scope(&pact_scope)?;
    Ok(FederationLifecycleAction {
        kind: FederationLifecycleKind::Connect,
        pact_id,
        grant_ref,
        peer_vault_id,
        pact_epoch: 1,
        scope_digest: Some(federation_scope_digest(&pact_nonce, &canonical)),
        pact_scope: Some(pact_scope),
        effective_scope: None,
        gesture: None,
        successor_vault_id: None,
        pact_nonce,
    })
}

/// This vault's id, once `issuer` is its live host root.
fn local_vault_id(fold: &AuthorityFold, issuer: &HostSlipIssuer) -> Result<AuthorityVaultId> {
    require_host(fold, issuer)?;
    fold.vault_id.ok_or_else(invalid_authority)
}

/// Refuses a `grant_ref` that is not a live FEDERATION_GRANT here.
fn require_live_grant(vault: &Vault, txn: &heed::RoTxn<'_>, grant_ref: &EntityId) -> Result<()> {
    match live_entity_row_in_txn(&vault.store, txn, grant_ref)? {
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_FEDERATION_GRANT,
            ..
        } => Ok(()),
        _ => Err(Error::EntityNotFound),
    }
}

/// Signs this host's half of `action` as an offer to its peer.
fn offer_for(
    issuer: &HostSlipIssuer,
    action: &FederationLifecycleAction,
    local: AuthorityVaultId,
) -> Result<ConnectOffer> {
    Ok(ConnectOffer {
        from_vault: local,
        to_vault: action.peer_vault_id,
        pact_id: action.pact_id,
        pact_nonce: action.pact_nonce,
        pact_scope: action.pact_scope.clone().ok_or_else(invalid_authority)?,
        gesture: issuer.sign_pact_gesture(action, &local)?,
    })
}

impl Vault {
    /// This vault's half of a new Connect with `peer_vault_id`, approved by
    /// `owner`: a fresh pact id and nonce, the scope pair (`outbound` is what
    /// this vault shares, `inbound` what the peer shares), and this host's
    /// gesture over the terms. Writes nothing: each log gets the pact only
    /// when its owner accepts the other host's half.
    pub fn propose_connect_as(
        &self,
        owner: &AuthenticatedOwner,
        issuer: &HostSlipIssuer,
        grant_ref: EntityId,
        peer_vault_id: AuthorityVaultId,
        outbound: FederationDirectionScope,
        inbound: FederationDirectionScope,
    ) -> Result<ConnectOffer> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let local = local_vault_id(&fold, issuer)?;
        if peer_vault_id == local {
            return Err(Error::InvalidConfig(
                "a vault cannot connect to itself".into(),
            ));
        }
        require_live_grant(self, &txn, &grant_ref)?;
        if fold.federation_grant_bindings.contains_key(&grant_ref) {
            return Err(Error::InvalidConfig(
                "this grant already governs a pact".into(),
            ));
        }
        // lo_to_hi is what the byte-wise smaller vault shares, the rule the
        // fold's `local_outbound_scope` reads back.
        let pact_scope = if local <= peer_vault_id {
            FederationPactScope {
                lo_to_hi: outbound,
                hi_to_lo: inbound,
            }
        } else {
            FederationPactScope {
                lo_to_hi: inbound,
                hi_to_lo: outbound,
            }
        };
        let mut pact_nonce = [0u8; 16];
        OsRng.fill_bytes(&mut pact_nonce);
        let action = connect_action(
            grant_ref,
            peer_vault_id,
            random_slip_id(),
            pact_nonce,
            pact_scope,
        )?;
        offer_for(issuer, &action, local)
    }

    /// Accepts the peer host's half of a Connect, approved by `owner`: logs
    /// the Connect for `grant_ref` with the peer's gesture, which the fold
    /// verifies and pins as the pact's peer owner key, and answers this
    /// host's half of the same terms for the peer's owner to accept. A repeat
    /// of the same terms logs nothing and answers the same.
    pub fn accept_connect_as(
        &self,
        owner: &AuthenticatedOwner,
        issuer: &HostSlipIssuer,
        grant_ref: EntityId,
        offer: &ConnectOffer,
    ) -> Result<(FederationPactState, ConnectOffer)> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let fold = self.authority_view_readonly_in_txn(txn)?;
            let local = local_vault_id(&fold, issuer)?;
            if offer.to_vault != local || offer.from_vault == local {
                return Err(Error::InvalidConfig(
                    "this Connect offer is not for this vault".into(),
                ));
            }
            require_live_grant(self, txn, &grant_ref)?;
            let mut action = connect_action(
                grant_ref,
                offer.from_vault,
                offer.pact_id,
                offer.pact_nonce,
                offer.pact_scope.clone(),
            )?;
            action.gesture = Some(offer.gesture.clone());
            let counter = offer_for(issuer, &action, local)?;
            let logged = fold.federation_pacts.get(&offer.pact_id).filter(|pact| {
                pact.grant_ref == grant_ref
                    && pact.peer_vault_id == offer.from_vault
                    && Some(pact.scope_digest) == action.scope_digest
                    && pact.peer_owner_key == offer.gesture.signer
            });
            if let Some(pact) = logged {
                return Ok((pact.clone(), counter));
            }
            self.append_slip_op_in_txn(txn, issuer, AuthorityOp::FederationLifecycle(action))?;
            let pact = self
                .authority_view_readonly_in_txn(txn)?
                .federation_pacts
                .get(&offer.pact_id)
                .cloned()
                .ok_or_else(invalid_authority)?;
            Ok((pact, counter))
        })
    }
}
