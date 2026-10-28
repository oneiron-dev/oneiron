//! `PUT /v1/llm/defaults` under the vault's policy power (FIX 8211). The
//! caller's own person proof goes to the core door, which lands a live
//! policy-power holder's table and keeps anyone else's as an inert
//! proposal; the credential's grade alone never replaces the defaults.

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use oneiron::consent::AuthenticatedOwner;
use oneiron::llm::{PurposeDefaultSubmission, PurposeDefaultSubmitter, PurposeDefaultTable};

use super::refusal;
use crate::api::owner_routes::machine_routes::act_surface;
use crate::{auth::CoreAuth, server::SyncServer};

/// Submits `table`, already validated, for the caller of `auth`: the owner
/// on his proof, his act recorded where it reached this install; another
/// person on their own verified human slip; any other principal by its id.
/// A holder's table answers `200` with the active table; anyone else's
/// answers `202` with the kept proposal, and the defaults stay as they are.
pub(super) fn submit(
    server: &SyncServer,
    auth: &CoreAuth,
    headers: &HeaderMap,
    table: &PurposeDefaultTable,
) -> Response {
    let owner = match crate::api::facade::owner_authorship(auth, server) {
        Ok(owner) => owner,
        Err(error) => return error.into_response(),
    };
    let now = crate::api::unix_seconds_now();
    let vault = &server.vault;
    let submitted = if let Some(owner) = &owner {
        let surface = Some(act_surface(server, auth, headers));
        vault.submit_purpose_default_table(PurposeDefaultSubmitter::Person(owner), table, surface, now)
    } else if let Some(person) = person(server, auth) {
        vault.submit_purpose_default_table(PurposeDefaultSubmitter::Person(&person), table, None, now)
    } else if let Some(principal) = auth.principal_entity() {
        vault.submit_purpose_default_table(
            PurposeDefaultSubmitter::Principal(principal),
            table,
            None,
            now,
        )
    } else {
        return refusal(StatusCode::FORBIDDEN, "owner_required");
    };
    match submitted {
        Ok(PurposeDefaultSubmission::Landed(table)) => Json(table).into_response(),
        Ok(PurposeDefaultSubmission::Proposed(proposal)) => (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({ "proposed": proposal })),
        )
            .into_response(),
        Err(oneiron::Error::InvalidConfig(_)) => {
            refusal(StatusCode::BAD_REQUEST, "invalid_defaults")
        }
        Err(oneiron::Error::Gate(_)) => refusal(StatusCode::FORBIDDEN, "owner_required"),
        Err(_) => refusal(StatusCode::INTERNAL_SERVER_ERROR, "defaults_unavailable"),
    }
}

/// A person's own proof on their own verified human slip, bound to that
/// slip so the writing transaction checks it again; `None` for any other
/// credential, or an invitee's.
fn person(server: &SyncServer, auth: &CoreAuth) -> Option<AuthenticatedOwner> {
    let slip = auth
        .verified_slip()
        .filter(|_| auth.actor_class() == Some("human"))?;
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
