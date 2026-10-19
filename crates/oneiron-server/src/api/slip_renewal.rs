//! FIX 3377: `POST /v1/core/slips/renew`, where a paired owner device renews
//! its own credential (Engine ruling rec a, 10-18).
//!
//! The request is an ordinary owner-grade one: `Authorization: Bearer
//! v2.slip.…` and its `x-oneiron-binding` holder proof, which the binding
//! door admits once, plus a mandatory `x-oneiron-machine` proof over that
//! same token, timestamp and nonce. The optional JSON `{"lifetime_secs": n}`
//! can only shorten the replacement. The reply is `{"token": "v2.slip.…"}`:
//! a fresh slip bound to the same key, which the device keeps beside the
//! seed it already holds. The engine judges every rule in its writer
//! (`Vault::renew_owner_device_slip`); this handler only refuses what is no
//! owner device's request at all (the development hatch, a host root, an
//! agent, a managed vault's attested owner with no slip of his own) and
//! hands the rest over raw. On a managed vault the device's own forwarded
//! slip and machine proof renew it as anywhere else (FIX 5126). Every engine
//! refusal is the same 401.

use std::sync::Arc;

use axum::{Json, extract::State, http::request::Parts};
use serde::{Deserialize, Serialize};

use crate::error::{ApiError, EnvelopedApiError};
use crate::server::SyncServer;

/// The optional body: a shorter lifetime than the credential's own.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RenewSlip {
    #[serde(default)]
    lifetime_secs: Option<u64>,
}

/// The replacement credential's slip token.
#[derive(Serialize)]
pub(super) struct RenewedSlip {
    token: String,
}

pub(super) async fn renew(
    parts: Parts,
    State(server): State<Arc<SyncServer>>,
    body: Option<Json<RenewSlip>>,
) -> Result<Json<RenewedSlip>, EnvelopedApiError> {
    let refused = || ApiError::forbidden_scope("owner-device");
    let requested_secs = body.and_then(|Json(body)| body.lifetime_secs);
    if requested_secs == Some(0) {
        return Err(ApiError::bad_request(
            "lifetime_secs must be a positive number of seconds",
            Some("lifetime_secs"),
        )
        .into());
    }
    let headers = &parts.headers;
    // On a managed vault the request's one caller, at owner grade, as the
    // legacy gate takes it anywhere else.
    let auth = match crate::auth::CoreAuth::for_managed_request(
        headers,
        &parts.extensions,
        crate::auth::request_path(&parts),
        &server,
    ) {
        Some(auth) => {
            let auth = auth?;
            if !auth.is_owner_grade() {
                return Err(ApiError::unauthorized().into());
            }
            auth
        }
        None => crate::auth::require_owner_auth(headers, &server.config, server.vault().as_ref())?,
    };
    // Only a verified human slip naming its holder is a device's own
    // credential: not the development hatch, a host root, an agent or an
    // attested owner without one.
    let current = auth
        .verified_slip()
        .filter(|_| auth.actor_class() == Some("human") && auth.principal_ref().is_some())
        .ok_or_else(refused)?;
    let device = crate::auth::required_machine_proof(headers)?;
    let renewed = super::pairing::with_issuer(&server, |issuer| {
        server
            .vault()
            .renew_owner_device_slip(issuer, current, &device, requested_secs)
    })?;
    let token = renewed.to_token().map_err(|_| ApiError::unauthorized())?;
    Ok(Json(RenewedSlip { token }))
}
