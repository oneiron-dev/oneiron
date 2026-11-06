//! Owner phone-line settings and credential-bound arrival metadata; no audio endpoint.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderName, StatusCode, header};
use axum::response::Json;
use axum::routing::{delete, get, post};
use oneiron::phone_line::{PhoneLineArrival, PhoneLineArrivalReceipt, PhoneLineConfig};
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;

use super::body_spool::OwnerJsonBody;
use super::openapi::OwnerRoute;
use super::owner_routes::{OwnerTable, blocking, owner};
use super::{core_engine_error, credential_read_key, unix_seconds_now};
use crate::auth::{CoreAuth, CoreScope};
use crate::error::{ApiError, ApiErrorEnvelope, EnvelopedApiError};
use crate::owner::OwnerError;
use crate::server::SyncServer;

type PrivateJson = ([(HeaderName, &'static str); 1], Json<Value>);
type OwnerPhoneReply = Result<PrivateJson, EnvelopedApiError>;

fn private_json(value: Value) -> PrivateJson {
    ([(header::CACHE_CONTROL, "no-store")], Json(value))
}

pub(crate) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/phone-lines/{identity_ref}",
                summary: "Read the owner's stored phone-line setting; 404 if never configured. Arrival metadata only, not an answering service.",
                row: None,
                shape: None,
            },
            get(get_phone_line),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/phone-lines/{identity_ref}",
                summary: "Store enabled and the explicit share_scope for this phone line. Enabling mints no read grant. A missing setting is off.",
                row: None,
                shape: None,
            },
            post(configure_phone_line),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/phone-lines/{identity_ref}/arrivals/{arrival_ref}",
                summary: "Read private arrival metadata by its opaque payload_ref, never a raw call id. Erased or unknown arrivals answer 404.",
                row: None,
                shape: None,
            },
            get(get_phone_line_arrival),
        ),
        (
            OwnerRoute {
                method: "delete",
                path: "/phone-lines/{identity_ref}/arrivals/{arrival_ref}",
                summary: "Erase private arrival metadata by its opaque payload_ref. Its retry marker prevents the same call from restoring erased text; 404 if absent.",
                row: None,
                shape: None,
            },
            delete(erase_phone_line_arrival),
        ),
    ]
}

async fn get_phone_line(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(identity_ref): Path<String>,
) -> OwnerPhoneReply {
    let proof = owner(&auth, &server)?;
    let identity = phone_identity(&identity_ref)?;
    let state = blocking(move || {
        server
            .vault()
            .phone_line_state_as(&proof, identity)
            .map_err(phone_engine)?
            .ok_or_else(|| OwnerError::NotFound("phone_line", identity.to_hex()))
    })
    .await?;
    Ok(private_json(serde_json::to_value(state).map_err(|_| {
        ApiError::internal_server_error("phone line state encode failed")
    })?))
}

async fn configure_phone_line(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(identity_ref): Path<String>,
    payload: OwnerJsonBody<PhoneLineConfig>,
) -> OwnerPhoneReply {
    let proof = owner(&auth, &server)?;
    let identity = phone_identity(&identity_ref)?;
    let desired = payload.read(&server).await?;
    let state = blocking(move || {
        server
            .vault()
            .configure_phone_line(&proof, identity, desired)
            .map_err(phone_engine)
    })
    .await?;
    Ok(private_json(serde_json::to_value(state).map_err(|_| {
        ApiError::internal_server_error("phone line state encode failed")
    })?))
}

async fn get_phone_line_arrival(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path((identity_ref, arrival_ref)): Path<(String, String)>,
) -> OwnerPhoneReply {
    let proof = owner(&auth, &server)?;
    let identity = phone_identity(&identity_ref)?;
    let record = blocking(move || {
        server
            .vault()
            .phone_line_arrival_by_ref_as(&proof, identity, &arrival_ref)
            .map_err(phone_engine)?
            .ok_or_else(|| OwnerError::NotFound("phone_line_arrival", arrival_ref))
    })
    .await?;
    Ok(private_json(serde_json::to_value(record).map_err(
        |_| ApiError::internal_server_error("phone line arrival encode failed"),
    )?))
}

async fn erase_phone_line_arrival(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path((identity_ref, arrival_ref)): Path<(String, String)>,
) -> OwnerPhoneReply {
    let proof = owner(&auth, &server)?;
    let identity = phone_identity(&identity_ref)?;
    blocking(move || {
        if server
            .vault()
            .erase_phone_line_arrival_by_ref_as(&proof, identity, &arrival_ref)
            .map_err(phone_engine)?
        {
            Ok(())
        } else {
            Err(OwnerError::NotFound("phone_line_arrival", arrival_ref))
        }
    })
    .await?;
    Ok(private_json(serde_json::json!({ "erased": true })))
}

/// Opaque queue references only. Private caller text remains in the native metadata row.
#[derive(Serialize, ToSchema)]
pub(crate) struct PhoneLineArrivalAck {
    payload_ref: String,
    correlation_id: String,
    attempt_ref: String,
    replayed: bool,
}

impl From<PhoneLineArrivalReceipt> for PhoneLineArrivalAck {
    fn from(receipt: PhoneLineArrivalReceipt) -> Self {
        Self {
            payload_ref: receipt.record.payload_ref,
            correlation_id: receipt.record.correlation_id,
            attempt_ref: receipt.record.attempt_ref,
            replayed: receipt.replayed,
        }
    }
}

#[utoipa::path(
    post,
    path = "/v1/core/phone-lines/{identity_ref}/arrivals",
    security(("CoreBearer" = [])),
    params(("identity_ref" = String, Path, description = "Receiving ChannelIdentity id")),
    request_body(content = Value, description = "Arrival metadata JSON: call_id (nonempty string) and caller (optional opaque string or null). No audio or transcript field."),
    responses(
        (status = 202, description = "Arrival metadata and inbox event committed. Exact call retries return the original opaque refs.", body = PhoneLineArrivalAck),
        (status = 400, description = "Invalid metadata or absent, disabled, mismatched or unreadable line", body = ApiErrorEnvelope),
        (status = 401, description = "Missing or invalid verified slip", body = ApiErrorEnvelope),
        (status = 403, description = "Credential lacks required read/write scope or registered principal", body = ApiErrorEnvelope),
        (status = 500, description = "Arrival admission failed", body = ApiErrorEnvelope)
    )
)]
pub(crate) async fn submit_core_phone_line_arrival(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(identity_ref): Path<String>,
    payload: OwnerJsonBody<PhoneLineArrival>,
) -> Result<
    (
        [(HeaderName, &'static str); 1],
        (StatusCode, Json<PhoneLineArrivalAck>),
    ),
    EnvelopedApiError,
> {
    if auth.verified_slip().is_none() {
        return Err(ApiError::unauthorized().into());
    }
    auth.require(CoreScope::Read)?;
    auth.require(CoreScope::Write)?;
    auth.require_registered_principal()?;
    let identity = phone_identity(&identity_ref)?;
    // This deferred JSON reader admits no authority; the credential door above does.
    let arrival = payload.read(&server).await?;
    let receipt = super::clock_ingress::run_blocking(move || {
        let vault = server.vault();
        let proof = auth.verified_slip().ok_or_else(ApiError::unauthorized)?;
        // No host/dev/attested-owner fallback can replace the submitted credential.
        let key = credential_read_key(vault, proof)?.for_destination(&auth.destination());
        let read = vault.scoped_read(key);
        vault
            .enqueue_phone_line_arrival_as(&read, identity, arrival, unix_seconds_now())
            .map_err(|error| core_engine_error("phone line arrival admission failed", error))
    })
    .await
    .map_err(|_| ApiError::internal_server_error("phone line admission task failed"))??;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        (
            StatusCode::ACCEPTED,
            Json(PhoneLineArrivalAck::from(receipt)),
        ),
    ))
}

fn phone_identity(identity_ref: &str) -> Result<oneiron::EntityId, ApiError> {
    oneiron::EntityId::from_hex(identity_ref)
        .map_err(|_| ApiError::bad_request("invalid identity_ref", Some("identity_ref")))
}

fn phone_engine(error: oneiron::Error) -> OwnerError {
    OwnerError::Engine(Box::new(error))
}
