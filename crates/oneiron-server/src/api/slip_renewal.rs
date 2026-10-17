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
//! owner device's request at all (a managed supervisor, the development
//! hatch, a host root, an agent) and hands the rest over raw. Every engine
//! refusal is the same 401.

use std::sync::Arc;

use axum::{Json, extract::State, http::HeaderMap};
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
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    body: Option<Json<RenewSlip>>,
) -> Result<Json<RenewedSlip>, EnvelopedApiError> {
    let refused = || ApiError::forbidden_scope("owner-device");
    // A managed supervisor authenticates as its host root, never as a device.
    if server.managed_issuer.is_some() {
        return Err(refused().into());
    }
    let requested_secs = body.and_then(|Json(body)| body.lifetime_secs);
    if requested_secs == Some(0) {
        return Err(ApiError::bad_request(
            "lifetime_secs must be a positive number of seconds",
            Some("lifetime_secs"),
        )
        .into());
    }
    let auth = crate::auth::require_owner_auth(&headers, &server.config, server.vault().as_ref())?;
    // Only a verified human slip naming its holder is a device's own
    // credential: not the development hatch, a host root or an agent.
    let current = auth
        .verified_slip()
        .filter(|_| auth.actor_class() == Some("human") && auth.principal_ref().is_some())
        .ok_or_else(refused)?;
    let device = crate::auth::required_machine_proof(&headers)?;
    let renewed = super::pairing::with_issuer(&server, |issuer| {
        server
            .vault()
            .renew_owner_device_slip(issuer, current, &device, requested_secs)
    })?;
    let token = renewed.to_token().map_err(|_| ApiError::unauthorized())?;
    Ok(Json(RenewedSlip { token }))
}
