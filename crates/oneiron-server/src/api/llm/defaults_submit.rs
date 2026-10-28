//! `PUT /v1/llm/defaults` under the vault's policy power (FIX 8211). The
//! caller's own person proof goes to the core door, which lands a live
//! policy-power holder's table and keeps anyone else's as an inert
//! proposal; the credential's grade alone never replaces the defaults.
//! `GET /v1/llm/defaults/proposals` lists the kept proposals, and
//! `POST /v1/llm/defaults/proposals/{proposal}` is a holder's answer to one.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use oneiron::authority::ActSurface;
use oneiron::consent::AuthenticatedOwner;
use oneiron::llm::{PurposeDefaultSubmission, PurposeDefaultSubmitter, PurposeDefaultTable};
use serde::Deserialize;

use super::refusal;
use crate::api::owner_routes::machine_routes::act_surface;
use crate::{auth::CoreAuth, server::SyncServer};

/// Submits `table`, already validated, for the caller of `auth`: the owner
/// on his proof, his act recorded where it reached this install; another
/// person on their own verified slip; any other principal by its id. A
/// holder's table answers `200` with the active table; anyone else's
/// answers `202` with the kept proposal, and the defaults stay as they are.
pub(super) fn submit(
    server: &SyncServer,
    auth: &CoreAuth,
    headers: &HeaderMap,
    table: &PurposeDefaultTable,
) -> Response {
    let now = crate::api::unix_seconds_now();
    let vault = &server.vault;
    let submitted = match person_of(server, auth, headers) {
        Err(refused) => return refused,
        Ok(Some((person, surface))) => vault.submit_purpose_default_table(
            PurposeDefaultSubmitter::Person(&person),
            table,
            surface,
            now,
        ),
        Ok(None) => match auth.principal_entity() {
            Some(principal) => vault.submit_purpose_default_table(
                PurposeDefaultSubmitter::Principal(principal),
                table,
                None,
                now,
            ),
            None => return refusal(StatusCode::FORBIDDEN, "owner_required"),
        },
    };
    match submitted {
        Ok(PurposeDefaultSubmission::Landed(table)) => Json(table).into_response(),
        Ok(PurposeDefaultSubmission::Proposed(proposal)) => (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({ "proposed": proposal })),
        )
            .into_response(),
        Err(error) => defaults_refusal(error),
    }
}

/// A holder's answer to one kept proposal.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProposalRuling {
    approve: bool,
}

/// `GET /v1/llm/defaults/proposals`: every kept proposal and where it
/// stands, read as the defaults themselves are read.
pub(super) async fn list_proposals(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> Response {
    if let Some(refused) = owner_grade_refusal(&server, &auth) {
        return refused;
    }
    if let Err(error) = crate::api::scoped_auth::require_live_managed_owner(&server, &auth) {
        return error.into_response();
    }
    match server.vault.purpose_default_proposals() {
        Ok(proposals) => Json(serde_json::json!({ "proposals": proposals })).into_response(),
        Err(error) => defaults_refusal(error),
    }
}

/// `POST /v1/llm/defaults/proposals/{proposal}`: a holder approves a kept
/// proposal, whose table then lands as the holder's own replacement, or
/// declines it. The caller's person proof and policy power are checked in
/// the ruling's own transaction; the answer is the proposal as it now stands.
pub(super) async fn rule_proposal(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(proposal): Path<String>,
    headers: HeaderMap,
    Json(ruling): Json<ProposalRuling>,
) -> Response {
    if let Some(refused) = owner_grade_refusal(&server, &auth) {
        return refused;
    }
    let (person, surface) = match person_of(&server, &auth, &headers) {
        Err(refused) => return refused,
        Ok(Some(found)) => found,
        Ok(None) => return refusal(StatusCode::FORBIDDEN, "policy_holder_required"),
    };
    let now = crate::api::unix_seconds_now();
    match server
        .vault
        .rule_purpose_default_proposal(&person, &proposal, ruling.approve, surface, now)
    {
        Ok(proposal) => Json(proposal).into_response(),
        Err(error) => defaults_refusal(error),
    }
}

/// The raw defaults routes' own admission: an owner-grade credential, and
/// no hosted operator's root acting as the owner (FIX 2222).
fn owner_grade_refusal(server: &SyncServer, auth: &CoreAuth) -> Option<Response> {
    if !auth.is_owner_grade() {
        return Some(refusal(StatusCode::FORBIDDEN, "owner_required"));
    }
    crate::api::host_action::require_host_owner_act(server, auth)
        .err()
        .map(IntoResponse::into_response)
}

/// A defaults door's error as its wire code.
fn defaults_refusal(error: oneiron::Error) -> Response {
    match error {
        oneiron::Error::InvalidConfig(_) => refusal(StatusCode::BAD_REQUEST, "invalid_defaults"),
        oneiron::Error::Gate(_) => refusal(StatusCode::FORBIDDEN, "owner_required"),
        oneiron::Error::Refused(_) => refusal(StatusCode::FORBIDDEN, "policy_holder_required"),
        oneiron::Error::EntityNotFound => refusal(StatusCode::NOT_FOUND, "proposal_not_found"),
        oneiron::Error::ConcurrentWrite(_) => refusal(StatusCode::CONFLICT, "proposal_answered"),
        _ => refusal(StatusCode::INTERNAL_SERVER_ERROR, "defaults_unavailable"),
    }
}

/// The caller's person proof, beside where the owner's act reached this
/// install: the owner on his proof (a credential of his that no longer
/// holds keeps its refusal); else a person on their own verified slip;
/// `None` for any other principal.
fn person_of(
    server: &SyncServer,
    auth: &CoreAuth,
    headers: &HeaderMap,
) -> Result<Option<(AuthenticatedOwner, Option<ActSurface>)>, Response> {
    let owner =
        crate::api::facade::owner_authorship(auth, server).map_err(IntoResponse::into_response)?;
    if let Some(owner) = owner {
        return Ok(Some((owner, Some(act_surface(server, auth, headers)))));
    }
    Ok(person(server, auth).map(|person| (person, None)))
}

/// A person's own proof on their own verified slip, bound to that slip so
/// the writing transaction checks it again. A slip that names no actor class
/// is judged by its holder: a stored live PERSON authenticates as one.
/// `None` for a slip of another class, an invitee's, or a holder that is no
/// stored person.
fn person(server: &SyncServer, auth: &CoreAuth) -> Option<AuthenticatedOwner> {
    let slip = auth
        .verified_slip()
        .filter(|_| matches!(auth.actor_class(), None | Some("human")))?;
    let principal = auth.principal_ref()?;
    let actor = oneiron::EntityId::from_hex(principal).ok()?;
    if slip.claims().holder_ref != actor.to_hex() || slip.claims().invitation_ref.is_some() {
        return None;
    }
    let person = server
        .vault
        .authenticate_owner(
            actor,
            principal,
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .ok()?;
    server
        .vault
        .bind_request_credential(person, slip.clone())
        .ok()
}
