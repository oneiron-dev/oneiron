//! Door for `oneiron-server/tests/selector_release_recheck.rs`
//! (SELECTOR-RELEASE-COREFERENCE-CONSENT = A): binds an Active federation
//! pact to a grant under the vault's live host root, as an accepted Connect
//! logs one, so a selector answer under that grant may carry a coreference
//! link only when its owner consented to share it into that pact.

use ed25519_dalek::{Signer, SigningKey};

use crate::Vault;
use crate::authority::{
    AuthorityKey, AuthorityOp, AuthorityVaultId, FederationGrantActivation,
    FederationLifecycleAction, FederationLifecycleKind, HostSlipIssuer,
    federation_grant_activation, federation_scope_digest, sign_federation_pact_gesture,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::{
    FederationDirectionScope, FederationPactScope, ScopeAxis, encode_federation_pact_scope,
};

/// The pact the door binds.
const PACT_ID: [u8; 32] = [0x63; 32];
/// The Connect's pact nonce.
const PACT_NONCE: [u8; 16] = [0x64; 16];
/// The key the pact's scope commitment is keyed by.
const SCOPE_KEY: [u8; 32] = [0x68; 32];
/// The peer vault the pact names; no vault the test opens.
const PEER_VAULT_ID: AuthorityVaultId = [0x65; 32];
/// The seed of the peer owner key whose gesture the Connect carries.
const PEER_KEY_SEED: [u8; 32] = [0x62; 32];

/// Binds an Active pact with every axis open to `grant_id`: a Connect
/// signed by the live host root `issuer`, carrying the peer owner's gesture
/// over its terms. Returns the pact id.
///
/// # Errors
///
/// An unrooted vault; encoding, signing or storage errors from the
/// authority-log door; a grant that does not read Active after the Connect.
pub fn bind_active_pact_to_grant(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    grant_id: EntityId,
) -> Result<[u8; 32]> {
    let vault_id = vault.authority_fold()?.vault_id.ok_or_else(|| {
        Error::InvalidConfig("the coreference pact door needs a rooted vault".into())
    })?;
    let open = FederationDirectionScope {
        worlds: ScopeAxis::All,
        facets: ScopeAxis::All,
        bands: ScopeAxis::All,
    };
    let pact_scope = FederationPactScope {
        lo_to_hi: open.clone(),
        hi_to_lo: open,
    };
    let scope_digest = federation_scope_digest(
        &SCOPE_KEY,
        &PACT_NONCE,
        &encode_federation_pact_scope(&pact_scope)?,
    );
    let peer = SigningKey::from_bytes(&PEER_KEY_SEED);
    let gesture = sign_federation_pact_gesture(
        FederationLifecycleKind::Connect,
        &PACT_ID,
        &vault_id,
        &PEER_VAULT_ID,
        1,
        &scope_digest,
        None,
        &PACT_NONCE,
        AuthorityKey::Ed25519(peer.verifying_key().to_bytes()),
        |transcript| Ok(peer.sign(transcript).to_bytes().to_vec()),
    )?;
    vault.log_host_op_for_test(
        issuer,
        AuthorityOp::FederationLifecycle(FederationLifecycleAction {
            kind: FederationLifecycleKind::Connect,
            pact_id: PACT_ID,
            grant_ref: grant_id,
            peer_vault_id: PEER_VAULT_ID,
            pact_epoch: 1,
            pact_scope: Some(pact_scope),
            effective_scope: None,
            scope_digest: Some(scope_digest),
            gesture: Some(gesture),
            successor_vault_id: None,
            pact_nonce: PACT_NONCE,
        }),
    )?;
    if federation_grant_activation(&vault.authority_fold()?, &grant_id)
        != FederationGrantActivation::Active
    {
        return Err(Error::InvalidConfig(
            "the coreference pact door's Connect left the grant not Active".into(),
        ));
    }
    Ok(PACT_ID)
}
