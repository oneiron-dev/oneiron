//! Host-only landing or decline of a frozen widen proposal. A transport login is not a holder action.
use super::super::json_payload;
use crate::{
    auth::{CoreAuth, CoreScope},
    error::{ApiError, ApiErrorEnvelope, EnvelopedApiError},
    managed::ManagedWidenHolder,
    server::SyncServer,
};
use axum::{
    Json,
    extract::{Extension, State, rejection::JsonRejection},
};
use oneiron::{ErrorKind, store::GateDecisionId};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct CoreAcceptWidenRequest {
    proposal_ref: String,
    /// Lowercase hex of the proposal's canonical, frozen delta.
    expected_delta: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreAcceptWidenResponse {
    decision_id: String,
    grant_ref: String,
}

/// A decline names only the proposal. Its body never parses as an accept
/// (no `expected_delta`) nor an accept's as a decline, so a managed holder
/// action signed over one body cannot answer the other way.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct CoreRejectWidenRequest {
    proposal_ref: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreRejectWidenResponse {
    decision_id: String,
}

/// The holder a widen answer runs as. Managed mode takes only a
/// supervisor-MACed account action installed by its socket middleware: a
/// host root by itself is never a holder. Unmanaged HTTP and local clients
/// use the same logged human slip door.
fn widen_holder<'a>(
    auth: &'a CoreAuth,
    server: &SyncServer,
    managed_holder: Option<Extension<ManagedWidenHolder>>,
) -> Result<
    (
        oneiron::EntityId,
        String,
        Option<&'a oneiron::authority::VerifiedSlip>,
    ),
    EnvelopedApiError,
> {
    if server.managed_issuer.is_some() {
        let actor = managed_holder
            .ok_or_else(|| ApiError::forbidden_scope("consent:widen:holder"))?
            .0
            .0;
        return Ok((actor, actor.to_hex(), None));
    }
    let credential = auth
        .verified_slip()
        .filter(|_| auth.actor_class() == Some("human"))
        .ok_or_else(|| ApiError::forbidden_scope("consent:widen:holder"))?;
    let principal = auth
        .principal_ref()
        .ok_or_else(|| ApiError::forbidden_scope("consent:widen:holder"))?;
    let actor = oneiron::EntityId::from_hex(principal)
        .map_err(|_| ApiError::forbidden_scope("consent:widen:holder"))?;
    Ok((actor, principal.to_owned(), Some(credential)))
}

/// A widen door's refusal as the route answers it.
fn widen_refusal(error: &oneiron::Error, failed: &'static str) -> ApiError {
    match error.kind() {
        ErrorKind::ConsentOwnerNotAuthenticated => {
            ApiError::forbidden_scope("consent:widen:holder")
        }
        ErrorKind::InvalidConsentGrantRow | ErrorKind::InvalidConsentBound => {
            ApiError::invalid_state(Some("consent_widen_proposal"))
        }
        _ => ApiError::internal_server_error(failed),
    }
}

#[utoipa::path(post, path="/v1/core/consent/widen/accept", request_body=CoreAcceptWidenRequest,
    responses((status=200,description="Holder accepted the proposal and minted a standing grant.",body=CoreAcceptWidenResponse),
        (status=400,description="Invalid request.",body=ApiErrorEnvelope),
        (status=401,description="Authentication required.",body=ApiErrorEnvelope),
        (status=403,description="Verified human holder with core:auth required.",body=ApiErrorEnvelope),
        (status=409,description="Proposal changed, expired, or already resolved.",body=ApiErrorEnvelope)))]
pub(crate) async fn core_accept_widen(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    managed_holder: Option<Extension<ManagedWidenHolder>>,
    payload: Result<Json<CoreAcceptWidenRequest>, JsonRejection>,
) -> Result<Json<CoreAcceptWidenResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Auth)?;
    let (actor, principal, credential) = widen_holder(&auth, &server, managed_holder)?;
    let req = json_payload(payload)?;
    let delta = req.expected_delta.as_bytes().chunks_exact(2);
    if !delta.remainder().is_empty() {
        return Err(ApiError::bad_request("invalid expected_delta", Some("expected_delta")).into());
    }
    let delta = delta
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .filter(|part| {
                    part.bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                })
                .and_then(|part| u8::from_str_radix(part, 16).ok())
        })
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| ApiError::bad_request("invalid expected_delta", Some("expected_delta")))?;
    let owner = server
        .vault()
        .authenticate_owner(actor, &principal, true, GateDecisionId::now())
        .map_err(|_| ApiError::forbidden_scope("consent:widen:holder"))?;
    let result = match credential {
        Some(credential) => {
            server
                .vault()
                .accept_credential_widen(&owner, credential, &req.proposal_ref, &delta)
        }
        None => server
            .vault()
            .accept_widen(&owner, &req.proposal_ref, &delta),
    };
    let receipt = result.map_err(|error| widen_refusal(&error, "widen approval failed"))?;
    Ok(Json(CoreAcceptWidenResponse {
        decision_id: receipt.decision_id().to_hex(),
        grant_ref: receipt
            .grant_ref()
            .ok_or_else(|| ApiError::invalid_state(Some("consent_widen_receipt")))?,
    }))
}

#[utoipa::path(post, path="/v1/core/consent/widen/reject", request_body=CoreRejectWidenRequest,
    responses((status=200,description="Holder declined the proposal; no later accept mints it.",body=CoreRejectWidenResponse),
        (status=400,description="Invalid request.",body=ApiErrorEnvelope),
        (status=401,description="Authentication required.",body=ApiErrorEnvelope),
        (status=403,description="Verified human holder with core:auth required.",body=ApiErrorEnvelope),
        (status=409,description="Proposal already resolved, or a contact-disclosure offer.",body=ApiErrorEnvelope)))]
pub(crate) async fn core_reject_widen(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    managed_holder: Option<Extension<ManagedWidenHolder>>,
    payload: Result<Json<CoreRejectWidenRequest>, JsonRejection>,
) -> Result<Json<CoreRejectWidenResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Auth)?;
    let (actor, principal, credential) = widen_holder(&auth, &server, managed_holder)?;
    let req = json_payload(payload)?;
    let owner = server
        .vault()
        .authenticate_owner(actor, &principal, true, GateDecisionId::now())
        .map_err(|_| ApiError::forbidden_scope("consent:widen:holder"))?;
    let result = match credential {
        Some(credential) => {
            server
                .vault()
                .reject_credential_widen(&owner, credential, &req.proposal_ref)
        }
        None => server.vault().reject_widen(&owner, &req.proposal_ref),
    };
    let receipt = result.map_err(|error| widen_refusal(&error, "widen decline failed"))?;
    Ok(Json(CoreRejectWidenResponse {
        decision_id: receipt.decision_id().to_hex(),
    }))
}
