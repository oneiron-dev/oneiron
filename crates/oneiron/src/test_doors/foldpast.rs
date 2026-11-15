//! Doors for `tests/foldpast_tail_scope.rs`: sign a host-root op as the next
//! row without storing it (or cosigned, or as another key), store signed
//! rows on a vault, and forget a first-seen receipt.

use crate::authority::{
    AuthorityKey, FederationLifecycleAction, FederationLifecycleKind, federation_scope_digest,
    sign_federation_pact_gesture,
};
use crate::authority::{AuthorityLogEntry, AuthorityOp, HostSlipIssuer};
use crate::error::Result;
use crate::federation::{
    FederationDirectionScope, FederationPactScope, ScopeAxis, encode_federation_pact_scope,
};
use crate::{EntityId, TimeRange, Vault};
use ed25519_dalek::{Signer, SigningKey};

/// Signs `op` as the host root's next row on `vault` without storing it.
///
/// # Errors
///
/// The fold's and the signer's.
pub fn sign_next_host_op(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    op: AuthorityOp,
) -> Result<AuthorityLogEntry> {
    vault.sign_host_op_for_test(issuer, op)
}

/// Signs `op` as the host root's next row on `vault`, cosigned by
/// `cosigner`, without storing it.
///
/// # Errors
///
/// The fold's and the signers'.
pub fn sign_next_host_op_cosigned(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    op: AuthorityOp,
    cosigner: &SigningKey,
) -> Result<AuthorityLogEntry> {
    vault.sign_host_op_cosigned_for_test(issuer, op, cosigner)
}

/// Signs `op` as `signing`'s next row on `vault`'s heads, without storing
/// it.
///
/// # Errors
///
/// The fold's and the signer's.
pub fn sign_next_op_as(
    vault: &Vault,
    signing: &SigningKey,
    op: AuthorityOp,
) -> Result<AuthorityLogEntry> {
    vault.sign_op_as_for_test(signing, op)
}

/// Deletes `vault`'s first-seen receipt of the row `hash`, as on a vault
/// that adopted its image before adoption kept receipts; whether one was
/// kept.
///
/// # Errors
///
/// The store's.
pub fn forget_first_seen_receipt(vault: &Vault, hash: &[u8; 32]) -> Result<bool> {
    vault.with_write_txn_grouped(|wtxn| {
        crate::authority::AUTHORITY_FIRST_SEEN.delete(
            &vault.store,
            wtxn,
            &crate::authority::authority_first_seen_sidecar_key(hash),
        )
    })
}

/// Stores `entries` on `vault` at its store clock.
///
/// # Errors
///
/// The authority log's.
pub fn put_signed_entries(vault: &Vault, entries: &[AuthorityLogEntry]) -> Result<()> {
    let now = vault.now_recorded_at();
    let at = TimeRange {
        start: now,
        end: now,
    };
    let rows: Vec<(AuthorityLogEntry, TimeRange, u64)> = entries
        .iter()
        .map(|entry| (entry.clone(), at, now))
        .collect();
    vault.put_authority_log_entries(&rows)?;
    Ok(())
}

/// Builds a Connect for a fresh pact, dual-signed by a fixed peer key.
///
/// # Errors
///
/// The fold's, the scope codec's, and the gesture's.
pub fn connect_action(vault: &Vault, grant_ref: EntityId) -> Result<FederationLifecycleAction> {
    let fold = vault.authority_fold()?;
    let local = fold
        .vault_id
        .ok_or_else(crate::authority::invalid_authority)?;
    let peer = SigningKey::from_bytes(&[0xC4; 32]);
    let peer_key = AuthorityKey::Ed25519(peer.verifying_key().to_bytes());
    let pact_id = [0xC1; 32];
    let peer_vault_id = [0xC2; 32];
    let pact_nonce = [0xC3; 16];
    let half = FederationDirectionScope {
        worlds: ScopeAxis::All,
        facets: ScopeAxis::All,
        bands: ScopeAxis::All,
    };
    let scope = FederationPactScope {
        lo_to_hi: half.clone(),
        hi_to_lo: half,
    };
    let encoded = encode_federation_pact_scope(&scope)?;
    let digest = federation_scope_digest(&[0x68; 32], &pact_nonce, &encoded);
    let gesture = sign_federation_pact_gesture(
        FederationLifecycleKind::Connect,
        &pact_id,
        &local,
        &peer_vault_id,
        1,
        &digest,
        None,
        &pact_nonce,
        peer_key,
        |transcript| Ok(peer.sign(transcript).to_bytes().to_vec()),
    )?;
    Ok(FederationLifecycleAction {
        kind: FederationLifecycleKind::Connect,
        pact_id,
        grant_ref,
        peer_vault_id,
        pact_epoch: 1,
        pact_scope: Some(scope),
        effective_scope: None,
        scope_digest: Some(digest),
        gesture: Some(gesture),
        successor_vault_id: None,
        pact_nonce,
    })
}

/// Builds the Disconnect for a connected pact.
pub fn disconnect_action(connect: &FederationLifecycleAction) -> FederationLifecycleAction {
    FederationLifecycleAction {
        kind: FederationLifecycleKind::Disconnect,
        pact_id: connect.pact_id,
        grant_ref: connect.grant_ref,
        peer_vault_id: connect.peer_vault_id,
        pact_epoch: connect.pact_epoch,
        pact_scope: None,
        effective_scope: None,
        scope_digest: None,
        gesture: None,
        successor_vault_id: None,
        pact_nonce: [0xC5; 16],
    }
}

/// Signs `op` as the host root's row at `seq` on `parents`, without storing
/// it: a row on a parent no head names, such as a rejected one.
///
/// # Errors
///
/// The fold's and the signer's.
pub fn sign_host_op_at(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    op: AuthorityOp,
    seq: u64,
    parents: Vec<crate::authority::AuthorityEntryHash>,
) -> Result<AuthorityLogEntry> {
    vault.sign_host_op_at_for_test(issuer, op, seq, parents)
}

/// The slip issuers `image`'s sequence index holds.
pub fn image_slip_issuers(
    image: &crate::authority::AuthorityCheckpointV2,
) -> std::collections::BTreeSet<crate::authority::AuthorityKey> {
    image.slip_issuers_for_test()
}
