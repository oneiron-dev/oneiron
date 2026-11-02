//! `POST /v1/owner/authority/clock/repair`: the owner's repair of a damaged
//! authority clock floor (FIX 10106), on its own ingress. A damaged floor
//! refuses every ordinary holder proof before its route runs, so this route
//! alone takes the owner's own full slip and its holder proof as they arrive
//! (the binding door spends nothing for it,
//! [`crate::auth::AUTHORITY_CLOCK_REPAIR_PATH`]) and hands them to the
//! engine, which judges both, and spends the proof's nonce, in the repair's
//! own writer against the floor it proves
//! (`Vault::repair_authority_clock_by_slip`). Only the owner's unattenuated
//! human slip binds there: a host root, an attenuated slip or another
//! person's slip acts as nobody. The answer is the repair's own: `sound`,
//! `repaired` or `unproven`; a vault that proves no clock at all answers
//! `authority_clock_corrupt`.

use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use axum::response::Json;
use axum::routing::post;
use oneiron::authority::{AuthorityClockRepair, CapabilitySlip};

use super::{OwnerReply, OwnerRoute, OwnerTable};
use crate::auth::{AUTHORITY_CLOCK_REPAIR_PATH, BindingProof, parse_signature};
use crate::error::{ApiError, ApiErrorDetails};
use crate::server::SyncServer;

/// Mounted under `/v1/owner`, at the one path the binding door leaves to
/// the repair.
pub(super) fn owner_table() -> OwnerTable {
    vec![(
        OwnerRoute {
            method: "post",
            path: AUTHORITY_CLOCK_REPAIR_PATH.trim_start_matches("/v1/owner"),
            summary: "Repair a damaged authority clock floor (FIX 10106) on its own ingress: the owner's own full human slip and its holder proof headers, which the engine judges, spending the proof's nonce, in the repair's own writer. Answers `sound`, `repaired` or `unproven`; a vault that proves no clock at all answers `authority_clock_corrupt`.",
            row: Some("vault.authority.clock.repair"),
        },
        post(repair),
    )]
}

/// The bearer slip token the request carries.
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

/// The engine's answer as this plane says it: a vault that proves no clock
/// names the damaged floor; an owner proof that does not hold is the owner
/// door's one refusal.
fn repair_error(error: oneiron::Error) -> ApiError {
    match error.kind() {
        oneiron::ErrorKind::AuthorityClockCorrupt => ApiError::new(
            error.to_string(),
            ApiErrorDetails::InvalidState {
                state: Some("authority_clock_corrupt".to_owned()),
            },
            ["This vault holds no observation that proves any clock; restore it from a backup."],
        ),
        oneiron::ErrorKind::ConsentOwnerNotAuthenticated => ApiError::forbidden_scope("owner"),
        _ => ApiError::unauthorized(),
    }
}

async fn repair(
    State(server): State<Arc<SyncServer>>,
    headers: HeaderMap,
) -> OwnerReply<AuthorityClockRepair> {
    let slip =
        CapabilitySlip::from_token(slip_token(&headers)?).map_err(|_| ApiError::unauthorized())?;
    let proof = BindingProof::from_headers(&headers)?;
    let signature = parse_signature(&proof.signature)?;
    let repaired = tokio::task::spawn_blocking(move || {
        server.vault().repair_authority_clock_by_slip(
            &slip,
            proof.timestamp,
            &signature,
            proof.nonce.as_bytes(),
        )
    })
    .await
    .map_err(|_| ApiError::internal_server_error("authority clock repair task failed"))?
    .map_err(repair_error)?;
    Ok(Json(repaired))
}
