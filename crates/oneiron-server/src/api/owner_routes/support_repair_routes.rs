//! `POST /v1/owner/support-repairs/run` (FIX 4407): the support holder's
//! door for one repair the customer selected in its support grant. It takes
//! the support slip (`Authorization: Bearer v2.slip.…`) and its holder proof
//! headers, as the authority clock repair does, and the engine admits the
//! slip, spends the proof and lands the grant's use receipt in one writer
//! ([`oneiron::Vault::run_support_repair_by_slip`]), so the binding door
//! spends none for this path ([`crate::auth::SUPPORT_REPAIR_PATH`]). No
//! owner credential reaches a repair here, and none needs to.

use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use axum::response::Json;
use axum::routing::post;
use oneiron::authority::{CapabilitySlip, SupportRepair};
use oneiron::housekeeping::HousekeepingReport;
use serde::Deserialize;

use super::{OwnerReply, OwnerRoute, OwnerTable};
use crate::auth::{BindingProof, SUPPORT_REPAIR_PATH, parse_signature};
use crate::error::ApiError;
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![(
        OwnerRoute {
            method: "post",
            path: SUPPORT_REPAIR_PATH.trim_start_matches("/v1/owner"),
            summary: "The support holder runs one repair the customer selected in its support grant (FIX 4407; `repair`), with the support slip and its holder proof headers; no owner credential reaches it. Answers the report of that one sweep; a slip that does not stand, or whose grant names no such repair, is refused as unauthorized and runs nothing.",
            row: None,
        },
        post(run),
    )]
}

/// The repair the support holder asks for, by its id.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SupportRepairRunRequest {
    repair: SupportRepair,
}

fn slip_token(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().split_once(char::is_whitespace))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
        .map(|(_, token)| token.trim())
        .filter(|token| token.starts_with("v2.slip."))
        .ok_or_else(ApiError::unauthorized)
}

/// Runs the one repair; the report names that sweep alone. A slip that does
/// not stand, or whose support grant names no such repair, is refused as
/// unauthorized and runs nothing.
async fn run(
    State(server): State<Arc<SyncServer>>,
    headers: HeaderMap,
    Json(request): Json<SupportRepairRunRequest>,
) -> OwnerReply<HousekeepingReport> {
    let slip =
        CapabilitySlip::from_token(slip_token(&headers)?).map_err(|_| ApiError::unauthorized())?;
    let proof = BindingProof::from_headers(&headers)?;
    let signature = parse_signature(&proof.signature)?;
    let budget = server.housekeeping_passes.support_repair_budget();
    let report = tokio::task::spawn_blocking(move || {
        server.vault().run_support_repair_by_slip(
            &slip,
            proof.timestamp,
            &signature,
            proof.nonce.as_bytes(),
            request.repair,
            budget,
        )
    })
    .await
    .map_err(|_| ApiError::internal_server_error("support repair task failed"))?
    .map_err(|_| ApiError::unauthorized())?;
    Ok(Json(report))
}
