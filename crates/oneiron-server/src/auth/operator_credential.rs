//! The host operator's own credential (FIX 1814, Engine ruling 10-29): a
//! slip apart from the host's root, for the operator's own doors.
//!
//! The host's root (holder `host`) acts on a self-hosted vault as the
//! vault's owner (FIX 2222), so an operator who holds it holds every owner
//! power. An operator credential is a slip of its own class, minted by the
//! same host issuer as the root (`oneiron token operator`): holder
//! `operator`, no parent, the one verb `operator`, and no actor class,
//! organization, records, channels, grant, invitation or delegation.
//!
//! It is a credential class, never a person and never an owner's proof. It
//! names no principal and holds no core scope, and it never becomes a
//! request's caller: [`CoreAuth`](super::CoreAuth) refuses its holder at
//! every door, as it refused it before this class existed. Only the
//! operator's doors (`/v1/operator/*`, `api::operator_routes`, through
//! `check_api_auth`) take it, and only on a self-hosted vault. The host's
//! root keeps its operator access there, and a managed vault's operator
//! gains nothing: its transport door and `check_api_auth` judge the
//! credential as they always did.

use axum::http::HeaderMap;
use oneiron::authority::{CapabilitySlip, SlipClaims};
use oneiron::federation::{Scope, ScopeAxis};

use super::{BindingProof, bearer_token, parse_signature};
use crate::error::ApiError;
use crate::server::SyncServer;

/// The holder an operator credential names: no entity, so no person (CALLS
/// `FIX 1814 operator credential class`).
pub(crate) const OPERATOR_HOLDER: &str = "operator";

/// The one verb an operator credential carries.
const OPERATOR_VERB: &str = "operator";

/// The root of the operator's own doors, the only paths that take one.
const OPERATOR_PATH_ROOT: &str = "/v1/operator/";

/// An operator credential a request at an operator door presented, its
/// holder proof verified ([`verified_operator`]). It names no caller and
/// carries no authority of a person or an owner; only the operator door
/// reads it.
pub(crate) struct OperatorCredential {
    slip_id: [u8; 32],
}

impl OperatorCredential {
    /// The credential's slip id, the one `oneiron token revoke` takes.
    pub(crate) fn slip_id(&self) -> [u8; 32] {
        self.slip_id
    }
}

/// The scope an operator credential carries: the one verb `operator`, so
/// no core scope reads from it.
fn operator_scope() -> Scope {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some([OPERATOR_VERB.to_owned()].into_iter().collect());
    scope
}

/// The claims of an operator credential for `binding_key` on the vault
/// `vault_id`, as the host issuer mints it: slip `slip_id`, from
/// `issued_at` until `expires_at`.
pub(crate) fn operator_slip_claims(
    vault_id: [u8; 32],
    slip_id: [u8; 32],
    binding_key: [u8; 32],
    issued_at: u64,
    expires_at: u64,
) -> SlipClaims {
    SlipClaims {
        slip_id,
        vault_id,
        parent_id: None,
        holder_ref: OPERATOR_HOLDER.to_owned(),
        binding_key,
        scope: operator_scope(),
        issued_at,
        expires_at,
        ttl_secs: expires_at.saturating_sub(issued_at),
        single_use: false,
        records: std::collections::BTreeSet::new(),
        channels: std::collections::BTreeSet::new(),
        actor_class: None,
        org_ref: None,
        grant_ref: None,
        invitation_ref: None,
        delegation: None,
        comm: None,
    }
}

/// Whether `slip` is an operator credential exactly as minted
/// ([`operator_slip_claims`]), with no caveat on it.
fn is_operator_class(slip: &CapabilitySlip) -> bool {
    let claims = &slip.claims;
    slip.caveats.is_empty()
        && claims.holder_ref == OPERATOR_HOLDER
        && claims.parent_id.is_none()
        && claims.scope == operator_scope()
        && !claims.single_use
        && claims.records.is_empty()
        && claims.channels.is_empty()
        && claims.actor_class.is_none()
        && claims.org_ref.is_none()
        && claims.grant_ref.is_none()
        && claims.invitation_ref.is_none()
        && claims.delegation.is_none()
}

/// The operator credential `token` is, presented at `path` on a
/// self-hosted vault's operator door; `None` for any other token, path or
/// vault.
fn operator_slip(server: &SyncServer, path: &str, token: &str) -> Option<CapabilitySlip> {
    if server.managed_issuer.is_some() || !path.starts_with(OPERATOR_PATH_ROOT) {
        return None;
    }
    CapabilitySlip::from_token(token)
        .ok()
        .filter(is_operator_class)
}

/// The transport door's admission of an operator credential (FIX 1814): at
/// a self-hosted vault's operator door, the holder proof `headers` carry
/// for `token` verified and spent once, as every slip's is, and returned.
/// `None` for any other request, which keeps the door's own path; `Some(Err)`
/// refuses a proof that does not verify, as that door refuses any slip's.
pub(super) fn bind_operator_once(
    server: &SyncServer,
    path: &str,
    token: &str,
    headers: &HeaderMap,
) -> Option<Result<BindingProof, ApiError>> {
    let slip = operator_slip(server, path, token)?;
    Some(spend_operator_proof(server, &slip, headers))
}

/// Spends the holder proof `headers` carry for the operator credential
/// `slip`, once.
fn spend_operator_proof(
    server: &SyncServer,
    slip: &CapabilitySlip,
    headers: &HeaderMap,
) -> Result<BindingProof, ApiError> {
    let proof = BindingProof::from_headers(headers)?;
    let signature = parse_signature(&proof.signature)?;
    server
        .vault()
        .admit_capability_slip_request(slip, proof.timestamp, &signature, proof.nonce.as_bytes())
        .map_err(|_| ApiError::unauthorized())?;
    // A fresh proof, used here once: the connection is no stranger's.
    crate::http_listener::authenticated();
    Ok(proof)
}

/// The operator credential a request to `path` with `headers` presents at a
/// self-hosted vault's operator door, verified read-only (the transport
/// door spent its proof once, [`bind_operator_once`]). `None` for any other
/// request, or a credential that does not verify: the door then judges the
/// request as it always did.
pub(crate) fn verified_operator(
    headers: &HeaderMap,
    path: &str,
    server: &SyncServer,
) -> Option<OperatorCredential> {
    let token = bearer_token(headers).ok().flatten()?;
    let slip = operator_slip(server, path, token)?;
    let proof = BindingProof::from_headers(headers).ok()?;
    let signature = parse_signature(&proof.signature).ok()?;
    let verified = server
        .vault()
        .verify_logged_capability_slip_request(
            &slip,
            proof.timestamp,
            &signature,
            proof.nonce.as_bytes(),
        )
        .ok()?;
    Some(OperatorCredential {
        slip_id: verified.claims().slip_id,
    })
}
