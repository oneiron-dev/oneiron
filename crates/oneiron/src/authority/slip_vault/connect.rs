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
    FederationDirectionScope, FederationPactScope, encode_federation_pact_scope, is_guest_slice,
    require_connect_grant_in_txn, require_one_connect_per_peer,
};
use crate::store::grant_scope_custody;

/// A pact epoch's scope opening key as an offer carries it (FIX 7907,
/// 7958): the secret its scope commitment is keyed by, carried between the
/// two hosts outside every signed record and logged nowhere. Each side's
/// custody holds it from its owner's accept until the pact is revoked. It
/// prints redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct ScopeOpeningKey(zeroize::Zeroizing<[u8; 32]>);

impl ScopeOpeningKey {
    /// The key whose 32 bytes are `bytes`, as an offer's carrier read it.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(zeroize::Zeroizing::new(bytes))
    }

    /// Its 32 bytes, for the offer's carrier.
    #[must_use]
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    /// A fresh key for a new pact epoch.
    pub(super) fn fresh() -> Result<Self> {
        Ok(Self(grant_scope_custody::new_scope_key()?))
    }
}

impl std::fmt::Debug for ScopeOpeningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ScopeOpeningKey(..)")
    }
}

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
    /// The scope opening key the commitment is keyed by, outside the
    /// gesture's transcript (FIX 7907, 7958).
    pub scope_key: ScopeOpeningKey,
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
/// epoch 1 and the scope pair's digest keyed by `scope_key`, with no gesture
/// yet.
fn connect_action(
    grant_ref: EntityId,
    peer_vault_id: AuthorityVaultId,
    pact_id: [u8; 32],
    pact_nonce: [u8; 16],
    pact_scope: FederationPactScope,
    scope_key: &ScopeOpeningKey,
) -> Result<FederationLifecycleAction> {
    let canonical = encode_federation_pact_scope(&pact_scope)?;
    Ok(FederationLifecycleAction {
        kind: FederationLifecycleKind::Connect,
        pact_id,
        grant_ref,
        peer_vault_id,
        pact_epoch: 1,
        scope_digest: Some(federation_scope_digest(
            scope_key.expose(),
            &pact_nonce,
            &canonical,
        )),
        pact_scope: Some(pact_scope),
        effective_scope: None,
        gesture: None,
        successor_vault_id: None,
        pact_nonce,
    })
}

/// This vault's id, once `issuer` is its live host root.
pub(super) fn local_vault_id(
    fold: &AuthorityFold,
    issuer: &HostSlipIssuer,
) -> Result<AuthorityVaultId> {
    require_host(fold, issuer)?;
    fold.vault_id.ok_or_else(invalid_authority)
}

/// Refuses a half whose peer direction no Connect guest grant can back:
/// what the peer shares is named worlds without base, as its own door
/// requires of its grant (FIX 3016).
fn require_peer_slice(inbound: &FederationDirectionScope) -> Result<()> {
    if is_guest_slice(inbound) {
        Ok(())
    } else {
        Err(Error::InvalidConfig(
            "the peer's half of a Connect must name worlds, never base".into(),
        ))
    }
}

/// Signs this host's half of `action` as an offer to its peer, carrying the
/// opening key `scope_key` its commitment is keyed by.
pub(super) fn offer_for(
    issuer: &HostSlipIssuer,
    action: &FederationLifecycleAction,
    local: AuthorityVaultId,
    scope_key: &ScopeOpeningKey,
) -> Result<ConnectOffer> {
    Ok(ConnectOffer {
        from_vault: local,
        to_vault: action.peer_vault_id,
        pact_id: action.pact_id,
        pact_nonce: action.pact_nonce,
        pact_scope: action.pact_scope.clone().ok_or_else(invalid_authority)?,
        gesture: issuer.sign_pact_gesture(action, &local)?,
        scope_key: scope_key.clone(),
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
        // The grant is this vault's Connect guest grant for the peer, and
        // `outbound` is its scope's projection; one live Connect per peer.
        require_connect_grant_in_txn(self, &txn, &grant_ref, &peer_vault_id, &outbound)?;
        require_peer_slice(&inbound)?;
        require_one_connect_per_peer(&fold, &peer_vault_id, None)?;
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
        let scope_key = ScopeOpeningKey::fresh()?;
        let action = connect_action(
            grant_ref,
            peer_vault_id,
            random_slip_id(),
            pact_nonce,
            pact_scope,
            &scope_key,
        )?;
        offer_for(issuer, &action, local, &scope_key)
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
            // The local outbound half is the one the fold's
            // `local_outbound_scope` reads back: lo_to_hi when this vault's
            // id is the smaller.
            let (outbound, inbound) = if local <= offer.from_vault {
                (&offer.pact_scope.lo_to_hi, &offer.pact_scope.hi_to_lo)
            } else {
                (&offer.pact_scope.hi_to_lo, &offer.pact_scope.lo_to_hi)
            };
            require_connect_grant_in_txn(self, txn, &grant_ref, &offer.from_vault, outbound)?;
            require_peer_slice(inbound)?;
            // An exact retry of this pact passes; any other live Connect with
            // the peer refuses.
            require_one_connect_per_peer(&fold, &offer.from_vault, Some(&offer.pact_id))?;
            let mut action = connect_action(
                grant_ref,
                offer.from_vault,
                offer.pact_id,
                offer.pact_nonce,
                offer.pact_scope.clone(),
                &offer.scope_key,
            )?;
            action.gesture = Some(offer.gesture.clone());
            let counter = offer_for(issuer, &action, local, &offer.scope_key)?;
            let logged = fold.federation_pacts.get(&offer.pact_id).filter(|pact| {
                pact.grant_ref == grant_ref
                    && pact.peer_vault_id == offer.from_vault
                    && Some(pact.scope_digest) == action.scope_digest
                    && pact.peer_owner_key == offer.gesture.signer
            });
            if let Some(pact) = logged {
                return Ok((pact.clone(), counter));
            }
            // The opening key enters custody with the Connect it keys.
            grant_scope_custody::install_scope_key(
                &self.store,
                txn,
                &grant_ref,
                &offer.pact_id,
                1,
                offer.scope_key.expose(),
            )?;
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
